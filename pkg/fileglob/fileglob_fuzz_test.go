package fileglob

import "testing"

// FuzzCompile exercises the pattern compiler on arbitrary strings.
// Contract: Compile must never panic. Malformed character classes,
// unterminated brackets, weird metacharacters — all must return an error,
// never a crash. A successfully-compiled pattern must also Match without
// panic on arbitrary targets.
func FuzzCompile(f *testing.F) {
	for _, seed := range []string{
		"",
		"/etc/kubernetes/pki/*.crt",
		"/var/**/*.pem",
		"/etc/[abc]*.crt",
		"/etc/[a-z]*.crt",
		"[",      // unterminated class
		"[!]",    // empty inverted class
		"[z-a]",  // inverted range
		"**/**",  // double recursive
		"a\\b",   // backslash
		"{a,b}",  // brace
		"\xff\x00\x01", // binary garbage
	} {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, pattern string) {
		p, err := Compile(pattern)
		if err != nil {
			return
		}
		_ = p.Match("/etc/kubernetes/pki/ca.crt")
		_ = p.Match("")
	})
}
