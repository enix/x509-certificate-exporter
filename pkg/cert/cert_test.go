package cert

import (
	"errors"
	"testing"
)

func TestSourceRefString(t *testing.T) {
	cases := []struct {
		name string
		ref  SourceRef
		want string
	}{
		{"file no key", SourceRef{Kind: "file", Location: "/etc/x.pem"}, "file:/etc/x.pem"},
		{"k8s with key", SourceRef{Kind: "kube-secret", Location: "ns/n", Key: "tls.crt"}, "kube-secret:ns/n#tls.crt"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.ref.String(); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestBundleHasFatalError(t *testing.T) {
	b := Bundle{}
	if b.HasFatalError() {
		t.Fatal("empty bundle has no fatal error")
	}
	b.Errors = append(b.Errors, ItemError{Index: 2, Reason: ReasonBadPEM, Err: errors.New("x")})
	if b.HasFatalError() {
		t.Fatal("per-item error is not fatal")
	}
	b.Errors = append(b.Errors, ItemError{Index: -1, Reason: ReasonBadPKCS12, Err: errors.New("y")})
	if !b.HasFatalError() {
		t.Fatal("Index==-1 is fatal")
	}
}
