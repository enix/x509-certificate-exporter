package fileglob

import (
	"context"
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// fakeFS adapts a fstest.MapFS into our WalkFS, with optional symlink support.
type fakeFS struct {
	tree    fstest.MapFS
	symlink map[string]string // path -> target
}

func (f *fakeFS) ReadDir(name string) ([]fs.DirEntry, error) {
	clean := strings.TrimPrefix(name, "/")
	if clean == "" {
		clean = "."
	}
	entries, err := f.tree.ReadDir(clean)
	if err != nil {
		return nil, err
	}
	// Patch symlink entries: report them as ModeSymlink.
	out := make([]fs.DirEntry, 0, len(entries))
	for _, e := range entries {
		full := path.Join(name, e.Name())
		if _, ok := f.symlink[full]; ok {
			out = append(out, &symlinkEntry{name: e.Name()})
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

func (f *fakeFS) Lstat(name string) (fs.FileInfo, error) {
	if _, ok := f.symlink[name]; ok {
		return &linkInfo{name: path.Base(name)}, nil
	}
	clean := strings.TrimPrefix(name, "/")
	if clean == "" {
		clean = "."
	}
	st, err := f.tree.Stat(clean)
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (f *fakeFS) Readlink(name string) (string, error) {
	if t, ok := f.symlink[name]; ok {
		return t, nil
	}
	return "", errors.New("not a symlink")
}

func (f *fakeFS) Stat(name string) (fs.FileInfo, error) {
	clean := strings.TrimPrefix(name, "/")
	if clean == "" {
		clean = "."
	}
	return f.tree.Stat(clean)
}

type symlinkEntry struct{ name string }

func (s *symlinkEntry) Name() string               { return s.name }
func (s *symlinkEntry) IsDir() bool                { return false }
func (s *symlinkEntry) Type() fs.FileMode          { return fs.ModeSymlink }
func (s *symlinkEntry) Info() (fs.FileInfo, error) { return &linkInfo{name: s.name}, nil }

type linkInfo struct{ name string }

func (l *linkInfo) Name() string       { return l.name }
func (l *linkInfo) Size() int64        { return 0 }
func (l *linkInfo) Mode() fs.FileMode  { return 0o777 | fs.ModeSymlink }
func (l *linkInfo) ModTime() time.Time { return time.Time{} }
func (l *linkInfo) IsDir() bool        { return false }
func (l *linkInfo) Sys() any           { return nil }

func compileMany(t *testing.T, pats ...string) []Pattern {
	t.Helper()
	out := make([]Pattern, 0, len(pats))
	for _, p := range pats {
		c, err := Compile(p)
		if err != nil {
			t.Fatalf("compile %q: %v", p, err)
		}
		out = append(out, c)
	}
	return out
}

func collect(ch <-chan Result) (entries []Entry, errs []*Error) {
	for r := range ch {
		if r.Err != nil {
			errs = append(errs, r.Err)
		} else {
			entries = append(entries, r.Entry)
		}
	}
	return
}

func TestCompileErrors(t *testing.T) {
	cases := []string{
		"",
		"foo/{a,b}",
		`foo\bar`,
		"foo/[abc",      // unterminated class
		"foo/[]",        // empty class
		"foo/[z-a]",     // inverted range
		"foo/**bar/baz", // ** not whole segment
		"foo/bar**",     // ** not whole segment
	}
	for _, p := range cases {
		if _, err := Compile(p); err == nil {
			t.Errorf("expected error for %q", p)
		}
	}
}

func TestCompileSuccess(t *testing.T) {
	for _, p := range []string{
		"/etc/x.pem",
		"/etc/**/*.pem",
		"/etc/?.pem",
		"/etc/[a-z].pem",
		"/etc/[!0-9].pem",
		"relative/*",
	} {
		if _, err := Compile(p); err != nil {
			t.Errorf("unexpected err for %q: %v", p, err)
		}
	}
}

func TestPatternMatch(t *testing.T) {
	cases := []struct {
		pat  string
		path string
		want bool
	}{
		{"/etc/x.pem", "/etc/x.pem", true},
		{"/etc/x.pem", "/etc/y.pem", false},
		{"/etc/*.pem", "/etc/x.pem", true},
		{"/etc/*.pem", "/etc/sub/x.pem", false},
		{"/etc/**/*.pem", "/etc/x.pem", true},
		{"/etc/**/*.pem", "/etc/a/b/x.pem", true},
		{"/etc/**/*.pem", "/etc/a/b/x.crt", false},
		{"/etc/?.pem", "/etc/a.pem", true},
		{"/etc/?.pem", "/etc/ab.pem", false},
		{"/etc/[a-c].pem", "/etc/b.pem", true},
		{"/etc/[a-c].pem", "/etc/d.pem", false},
		{"/etc/[!a-c].pem", "/etc/d.pem", true},
		{"/etc/[!a-c].pem", "/etc/a.pem", false},
		{"/a/b", "/a/b/", true},
		{"/a/**", "/a", true},
		{"/a/**", "/a/x/y", true},
	}
	for _, c := range cases {
		t.Run(c.pat+"#"+c.path, func(t *testing.T) {
			p := MustCompile(c.pat)
			if got := p.Match(c.path); got != c.want {
				t.Errorf("Match(%q) on %q: got %v want %v", c.path, c.pat, got, c.want)
			}
		})
	}
}

func TestWalkBasic(t *testing.T) {
	tree := fstest.MapFS{
		"etc/kubernetes/pki/ca.crt":        {Data: []byte("ca")},
		"etc/kubernetes/pki/apiserver.crt": {Data: []byte("apiserver")},
		"etc/kubernetes/pki/apiserver.key": {Data: []byte("k")},
		"etc/kubernetes/pki/etcd/peer.crt": {Data: []byte("peer")},
		"etc/other/junk.txt":               {Data: []byte("x")},
	}
	fsys := &fakeFS{tree: tree, symlink: map[string]string{}}
	pats := compileMany(t, "/etc/kubernetes/pki/**/*.crt")
	res := Walk(context.Background(), Options{Includes: pats, FS: fsys})
	entries, errs := collect(res)
	if len(errs) != 0 {
		t.Fatalf("unexpected errs: %v", errs)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d: %+v", len(entries), entries)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Path, ".crt") {
			t.Errorf("non-.crt leaked: %s", e.Path)
		}
	}
}

func TestWalkExcludes(t *testing.T) {
	tree := fstest.MapFS{
		"a/x.pem":     {Data: []byte("x")},
		"a/sub/y.pem": {Data: []byte("y")},
		"a/sub/z.pem": {Data: []byte("z")},
	}
	pats := compileMany(t, "/a/**/*.pem")
	excludes := compileMany(t, "/a/sub/**")
	res := Walk(context.Background(), Options{
		Includes: pats, Excludes: excludes, FS: &fakeFS{tree: tree, symlink: map[string]string{}},
	})
	entries, _ := collect(res)
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Path, "/a/x.pem") {
		t.Fatalf("excludes should hide /a/sub/**: got %+v", entries)
	}
}

func TestWalkSymlinkFile(t *testing.T) {
	tree := fstest.MapFS{
		"real/x.pem": {Data: []byte("x")},
		"link":       {Data: []byte("placeholder")}, // existence so MapFS knows the dir entry
	}
	fsys := &fakeFS{tree: tree, symlink: map[string]string{"/link": "real/x.pem"}}
	pats := compileMany(t, "/*")
	res := Walk(context.Background(), Options{Includes: pats, FollowSymlinks: true, FS: fsys})
	entries, _ := collect(res)
	found := false
	for _, e := range entries {
		if e.Path == "/link" && e.LinkTo == "/real/x.pem" {
			found = true
		}
	}
	if !found {
		t.Fatalf("symlink entry not produced: %+v", entries)
	}
}

func TestWalkSymlinkDirIgnored(t *testing.T) {
	tree := fstest.MapFS{
		"real/x.pem": {Data: []byte("x")},
		"realDir":    {Mode: fs.ModeDir | 0o755},
		"link":       {Data: []byte("placeholder")},
	}
	// Symlink "/link" -> "real" (a directory). We expect NO entry produced
	// even though FollowSymlinks=true (because target is a dir).
	fsys := &fakeFS{tree: tree, symlink: map[string]string{"/link": "real"}}
	pats := compileMany(t, "/link/*.pem")
	res := Walk(context.Background(), Options{Includes: pats, FollowSymlinks: true, FollowSymlinkDirs: false, FS: fsys})
	entries, _ := collect(res)
	for _, e := range entries {
		if strings.HasPrefix(e.Path, "/link") {
			t.Errorf("symlink-to-dir should not yield entries unless FollowSymlinkDirs: %s", e.Path)
		}
	}
}

func TestWalkBrokenSymlink(t *testing.T) {
	tree := fstest.MapFS{
		"link": {Data: []byte("p")},
	}
	fsys := &fakeFS{tree: tree, symlink: map[string]string{"/link": "/nonexistent"}}
	pats := compileMany(t, "/*")
	res := Walk(context.Background(), Options{Includes: pats, FollowSymlinks: true, FS: fsys})
	entries, errs := collect(res)
	if len(entries) != 0 {
		t.Fatalf("want no entries for broken symlink, got %+v", entries)
	}
	if len(errs) == 0 || errs[0].Reason != "broken_symlink" {
		t.Fatalf("want broken_symlink error, got %+v", errs)
	}
}

func TestWalkMissingDir(t *testing.T) {
	pats := compileMany(t, "/nope/**/*.pem")
	res := Walk(context.Background(), Options{Includes: pats, FS: &fakeFS{tree: fstest.MapFS{}, symlink: map[string]string{}}})
	_, errs := collect(res)
	if len(errs) == 0 {
		t.Fatalf("want error for missing dir")
	}
}

func TestWalkContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tree := fstest.MapFS{"a/x": {Data: []byte("x")}}
	pats := compileMany(t, "/a/*")
	res := Walk(ctx, Options{Includes: pats, FS: &fakeFS{tree: tree, symlink: map[string]string{}}})
	_, _ = collect(res)
	// We just check the channel closes cleanly.
}

func TestWalkLiteralPattern(t *testing.T) {
	tree := fstest.MapFS{
		"etc/x.pem": {Data: []byte("x")},
	}
	pats := compileMany(t, "/etc/x.pem")
	res := Walk(context.Background(), Options{Includes: pats, FS: &fakeFS{tree: tree, symlink: map[string]string{}}})
	entries, _ := collect(res)
	if len(entries) != 1 || entries[0].Path != "/etc/x.pem" {
		t.Fatalf("literal pattern should match exactly that path: %+v", entries)
	}
}

func TestWalkDoublestarOnly(t *testing.T) {
	tree := fstest.MapFS{
		"a/b/c.pem": {Data: []byte("x")},
		"a/d.pem":   {Data: []byte("y")},
	}
	pats := compileMany(t, "/a/**")
	res := Walk(context.Background(), Options{Includes: pats, FS: &fakeFS{tree: tree, symlink: map[string]string{}}})
	entries, _ := collect(res)
	if len(entries) < 2 {
		t.Fatalf("** should match all descendants, got %+v", entries)
	}
}

func TestWalkMaxDepth(t *testing.T) {
	tree := fstest.MapFS{
		"a/b/c/d/e/leaf.pem": {Data: []byte("x")},
	}
	pats := compileMany(t, "/a/**/*.pem")
	res := Walk(context.Background(), Options{Includes: pats, FS: &fakeFS{tree: tree, symlink: map[string]string{}}, MaxDepth: 2})
	entries, _ := collect(res)
	for _, e := range entries {
		if strings.Count(e.Path, "/") > 4 { // /a/b/c is depth 2 from /a
			t.Errorf("MaxDepth violated: %s", e.Path)
		}
	}
}

func TestErrorString(t *testing.T) {
	e := &Error{Path: "/x", Reason: "broken_symlink", Err: errors.New("boom")}
	if !strings.Contains(e.Error(), "broken_symlink") {
		t.Fail()
	}
	var nilErr *Error
	if nilErr.Error() != "<nil>" {
		t.Fail()
	}
}
