package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultsApplied(t *testing.T) {
	c := Default()
	if c.Server.Listen != ":9793" {
		t.Fail()
	}
	if c.Metrics.CollisionDiscriminator != "auto" {
		t.Fail()
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(path, []byte(`
server:
  listen: :8080
log:
  level: debug
sources:
  - kind: file
    name: test
    paths: ["/etc/x.pem"]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":8080" {
		t.Errorf("listen override: %q", c.Server.Listen)
	}
	if c.Log.Level != "debug" {
		t.Errorf("log level override: %q", c.Log.Level)
	}
	if len(c.Sources) != 1 || c.Sources[0].Kind != "file" {
		t.Errorf("sources: %+v", c.Sources)
	}
	if c.Sources[0].FollowSymlinks == nil || !*c.Sources[0].FollowSymlinks {
		t.Errorf("default followSymlinks should be true")
	}
}

func TestValidateRejectsBadCollision(t *testing.T) {
	c := Default()
	c.Metrics.CollisionDiscriminator = "yolo"
	if err := Validate(c); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateSourceKind(t *testing.T) {
	c := Default()
	c.Sources = []Source{{Kind: "", Name: "x"}}
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("got %v", err)
	}
	c.Sources = []Source{{Kind: "weird", Name: "x"}}
	if err := Validate(c); err == nil {
		t.Fatal("expected unknown kind error")
	}
}

func TestValidateFilePathsRequired(t *testing.T) {
	c := Default()
	c.Sources = []Source{{Kind: "file", Name: "x"}}
	if err := Validate(c); err == nil {
		t.Fatal("expected paths error")
	}
}

func TestValidateFileFormatChecked(t *testing.T) {
	c := Default()
	c.Sources = []Source{{Kind: "file", Name: "x", Paths: []string{"/x"}, Formats: []string{"weird"}}}
	if err := Validate(c); err == nil {
		t.Fatal("expected format error")
	}
}

func TestValidateKubeconfigPathsRequired(t *testing.T) {
	c := Default()
	c.Sources = []Source{{Kind: "kubeconfig", Name: "x"}}
	if err := Validate(c); err == nil {
		t.Fatal("expected paths error")
	}
}

func TestValidateKubernetesNeedsResources(t *testing.T) {
	c := Default()
	c.Sources = []Source{{Kind: "kubernetes", Name: "x"}}
	if err := Validate(c); err == nil {
		t.Fatal("expected secrets/configMaps error")
	}
}

func TestApplyCLI(t *testing.T) {
	c := ApplyCLI(Default(), CLIOverrides{
		WatchFiles:       []string{"/etc/x.pem"},
		WatchDirs:        []string{"/etc/ssl/certs/"},
		WatchKubeconf:    []string{"/etc/kubernetes/admin.conf"},
		WatchKubeSecrets: true,
		Listen:           ":1234",
		Debug:            true,
		Profile:          true,
	})
	if c.Server.Listen != ":1234" {
		t.Fail()
	}
	if c.Log.Level != "debug" {
		t.Fail()
	}
	if !c.Diagnostics.Pprof.Enabled {
		t.Fail()
	}
	kinds := map[string]int{}
	for _, s := range c.Sources {
		kinds[s.Kind]++
	}
	if kinds["file"] != 2 || kinds["kubeconfig"] != 1 || kinds["kubernetes"] != 1 {
		t.Fatalf("sources: %+v", kinds)
	}
	if err := Validate(c); err != nil {
		t.Fatalf("synthesized config invalid: %v", err)
	}
}

func TestFindAndLoadExplicit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	_ = os.WriteFile(p, []byte("server:\n  listen: \":99\"\n"), 0o600)
	c, gotPath, err := FindAndLoad(p)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != p {
		t.Errorf("path %q want %q", gotPath, p)
	}
	if c.Server.Listen != ":99" {
		t.Errorf("listen %q", c.Server.Listen)
	}
}

func TestFindAndLoadMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	if _, _, err := FindAndLoad(""); err == nil {
		t.Fatal("expected error")
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("/etc/ssl/certs"); got != "etc-ssl-certs" {
		t.Errorf("got %q", got)
	}
	if got := sanitize("///"); got != "anon" {
		t.Errorf("got %q", got)
	}
}

func TestHasSourcesAndPaths(t *testing.T) {
	c := Default()
	if HasSources(c) {
		t.Fail()
	}
	c.Sources = []Source{{Kind: "file", Paths: []string{"/x", "/y"}}}
	if !HasSources(c) {
		t.Fail()
	}
	if got := SourcePaths(c); len(got) != 2 {
		t.Fail()
	}
}
