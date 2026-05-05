// Package fileglob implements a small, dedicated glob/walk engine for
// certificate discovery. It is NOT a general-purpose glob library.
//
// Supported pattern tokens:
//
//   - match within a single segment, never across "/"
//     ?                match exactly one character within a segment
//     [abc] [a-z] [!a-z]   character class
//     **               match zero or more whole segments (recursive)
//
// Anything else (notably braces and backslash escapes) is rejected at
// pattern compile time. This is deliberate: certificate paths in the wild
// never use those, and rejecting them keeps the matcher simple and safe.
//
// The walker descends only into directories that can still match the
// remaining segments (short-circuit). Symlinks are inspected via Lstat;
// the policy for following them is configurable per-walk.
package fileglob

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/enix/x509-certificate-exporter/v4/pkg/cert"
)

// Pattern is a compiled glob pattern.
type Pattern struct {
	raw      string
	prefix   string    // longest static prefix without meta tokens
	segments []segment // remaining segments after the prefix
}

// Raw returns the source pattern.
func (p Pattern) Raw() string { return p.raw }

// segment is a compiled match unit for one path segment.
type segment struct {
	literal     string    // when kind == segLiteral
	parts       []segPart // when kind == segGlob: ordered parts for matching
	kind        segKind
	hasWildcard bool
}

type segKind int

const (
	segLiteral segKind = iota
	segGlob
	segDoublestar
)

// segPart represents a piece of a glob segment between wildcards.
// kind: 0=literal, 1=any('?'), 2=class
type segPart struct {
	kind  int
	lit   string
	class charClass
}

type charClass struct {
	negate bool
	ranges []charRange
}

type charRange struct {
	lo, hi rune
}

// Compile parses a pattern string. Pattern paths must be absolute or be
// relative to the caller's working directory; they are not normalized
// further. Returns an error for unsupported tokens or syntactically
// invalid character classes.
func Compile(pattern string) (Pattern, error) {
	if pattern == "" {
		return Pattern{}, fmt.Errorf("empty pattern")
	}
	if strings.ContainsAny(pattern, "{}\\") {
		return Pattern{}, fmt.Errorf("unsupported meta-character in pattern %q (braces and backslash escapes are not allowed)", pattern)
	}
	clean := pattern
	// Split into segments. We preserve absoluteness by tracking the leading
	// slash as part of the prefix.
	abs := strings.HasPrefix(clean, "/")
	parts := strings.Split(strings.Trim(clean, "/"), "/")
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
		return Pattern{}, fmt.Errorf("empty pattern after trimming")
	}

	// Find the longest static prefix.
	prefixEnd := 0
	for i, p := range parts {
		if hasMeta(p) || p == "**" {
			break
		}
		prefixEnd = i + 1
	}
	prefixSegs := parts[:prefixEnd]
	tailSegs := parts[prefixEnd:]

	// If the pattern is purely static (no glob segments at all), move the
	// last static component into the tail so that the walker descends into
	// the parent directory and matches the leaf as a literal segment.
	if len(tailSegs) == 0 && len(prefixSegs) > 0 {
		last := prefixSegs[len(prefixSegs)-1]
		prefixSegs = prefixSegs[:len(prefixSegs)-1]
		tailSegs = []string{last}
	}

	pref := strings.Join(prefixSegs, "/")
	if abs {
		pref = "/" + pref
	}
	if pref == "" {
		pref = "."
	}

	segs := make([]segment, 0, len(tailSegs))
	for _, s := range tailSegs {
		seg, err := compileSegment(s)
		if err != nil {
			return Pattern{}, fmt.Errorf("bad segment %q in pattern %q: %w", s, pattern, err)
		}
		segs = append(segs, seg)
	}

	return Pattern{raw: pattern, prefix: pref, segments: segs}, nil
}

// MustCompile is the test-friendly variant.
func MustCompile(pattern string) Pattern {
	p, err := Compile(pattern)
	if err != nil {
		panic(err)
	}
	return p
}

func hasMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

func compileSegment(s string) (segment, error) {
	if s == "**" {
		return segment{kind: segDoublestar}, nil
	}
	if !hasMeta(s) {
		return segment{kind: segLiteral, literal: s}, nil
	}
	if strings.Contains(s, "**") {
		return segment{}, fmt.Errorf("** must be a whole segment")
	}
	parts, err := compileGlobSegment(s)
	if err != nil {
		return segment{}, err
	}
	return segment{kind: segGlob, parts: parts, hasWildcard: true}, nil
}

func compileGlobSegment(s string) ([]segPart, error) {
	var parts []segPart
	var lit strings.Builder
	flush := func() {
		if lit.Len() > 0 {
			parts = append(parts, segPart{kind: 0, lit: lit.String()})
			lit.Reset()
		}
	}
	for i := 0; i < len(s); {
		ch := s[i]
		switch ch {
		case '*':
			flush()
			parts = append(parts, segPart{kind: 100}) // marker for *
			i++
		case '?':
			flush()
			parts = append(parts, segPart{kind: 1})
			i++
		case '[':
			flush()
			cls, n, err := parseClass(s[i:])
			if err != nil {
				return nil, err
			}
			parts = append(parts, segPart{kind: 2, class: cls})
			i += n
		default:
			lit.WriteByte(ch)
			i++
		}
	}
	flush()
	return parts, nil
}

func parseClass(s string) (charClass, int, error) {
	if len(s) < 2 || s[0] != '[' {
		return charClass{}, 0, fmt.Errorf("bad class")
	}
	i := 1
	negate := false
	if i < len(s) && s[i] == '!' {
		negate = true
		i++
	}
	var ranges []charRange
	for i < len(s) && s[i] != ']' {
		lo := rune(s[i])
		hi := lo
		if i+2 < len(s) && s[i+1] == '-' && s[i+2] != ']' {
			hi = rune(s[i+2])
			if hi < lo {
				return charClass{}, 0, fmt.Errorf("inverted range %c-%c", lo, hi)
			}
			i += 3
		} else {
			i++
		}
		ranges = append(ranges, charRange{lo: lo, hi: hi})
	}
	if i >= len(s) {
		return charClass{}, 0, fmt.Errorf("unterminated class")
	}
	if len(ranges) == 0 {
		return charClass{}, 0, fmt.Errorf("empty class")
	}
	return charClass{negate: negate, ranges: ranges}, i + 1, nil
}

// matchSegment evaluates one segment against a path component.
func matchSegment(seg segment, name string) bool {
	switch seg.kind {
	case segLiteral:
		return seg.literal == name
	case segGlob:
		return matchGlob(seg.parts, name)
	case segDoublestar:
		return true
	}
	return false
}

// matchGlob is the core single-segment matcher with backtracking on '*'.
// '*' matches any run of bytes within the segment (no '/').
func matchGlob(parts []segPart, s string) bool {
	type frame struct{ pi, si int }
	var stack []frame
	pi, si := 0, 0
	for {
		if pi == len(parts) {
			if si == len(s) {
				return true
			}
		} else {
			p := parts[pi]
			switch p.kind {
			case 0: // literal
				if strings.HasPrefix(s[si:], p.lit) {
					si += len(p.lit)
					pi++
					continue
				}
			case 1: // ?
				if si < len(s) {
					si++
					pi++
					continue
				}
			case 2: // class
				if si < len(s) && p.class.match(rune(s[si])) {
					si++
					pi++
					continue
				}
			case 100: // *
				// push a backtrack frame: try matching '*' with one more
				// char on next failure.
				stack = append(stack, frame{pi: pi, si: si + 1})
				pi++
				continue
			}
		}
		// failure: pop a backtrack frame
		if len(stack) == 0 {
			return false
		}
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if top.si > len(s) {
			continue
		}
		pi, si = top.pi, top.si
	}
}

func (c charClass) match(r rune) bool {
	hit := false
	for _, rng := range c.ranges {
		if r >= rng.lo && r <= rng.hi {
			hit = true
			break
		}
	}
	if c.negate {
		return !hit
	}
	return hit
}

// matchAll matches a list of path segments against pattern segments.
// It is exported only for testing; the regular path is Walk.
func matchAll(segs []segment, parts []string) bool {
	return matchAllRec(segs, 0, parts, 0)
}

func matchAllRec(segs []segment, si int, parts []string, pi int) bool {
	for si < len(segs) && pi <= len(parts) {
		s := segs[si]
		if s.kind == segDoublestar {
			// try absorbing 0..N segments
			for k := pi; k <= len(parts); k++ {
				if matchAllRec(segs, si+1, parts, k) {
					return true
				}
			}
			return false
		}
		if pi == len(parts) {
			return false
		}
		if !matchSegment(s, parts[pi]) {
			return false
		}
		si++
		pi++
	}
	// Consume trailing **s (which can match zero segments).
	for si < len(segs) && segs[si].kind == segDoublestar {
		si++
	}
	return si == len(segs) && pi == len(parts)
}

// Match returns true if the cleaned absolute (or relative) path matches the
// compiled pattern. Trailing slashes are ignored.
func (p Pattern) Match(target string) bool {
	target = strings.TrimRight(target, "/")
	prefix := strings.TrimRight(p.prefix, "/")
	if prefix != "." {
		if !strings.HasPrefix(target, prefix) {
			return false
		}
		target = strings.TrimPrefix(target, prefix)
		target = strings.TrimPrefix(target, "/")
	}
	if target == "" {
		// No tail: must match an empty segment list.
		return matchAll(p.segments, nil)
	}
	parts := strings.Split(target, "/")
	return matchAll(p.segments, parts)
}

// Entry is one walked filesystem entry.
type Entry struct {
	Path    string      // path as a caller would see it (Lstat-ed)
	Pattern string      // pattern that matched, for debug/labels
	Info    fs.FileInfo // result of Lstat — Mode().Type() distinguishes
	LinkTo  string      // resolved target if Info is a symlink and FollowSymlinks; "" otherwise
}

// Result is one item produced on the walk channel. Either Entry or Err is
// set, not both.
type Result struct {
	Entry Entry
	Err   *Error
}

// Error wraps a walk-time error with the path it concerns. The walk does
// not abort on errors; it produces an Error result and continues.
type Error struct {
	Path   string
	Reason string // canonical reason from cert.Reason* (broken_symlink, walk_error, permission_denied, ...)
	Err    error
}

func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.Reason + " on " + e.Path + ": " + e.Err.Error()
}

// PathMapping rewrites an absolute path-prefix encountered while resolving
// symlinks. It is used when a foreign filesystem (typically a host's view,
// reachable through a bind-mount) is mounted at a different path inside the
// walker's local view: a symlink may then point at the foreign path it sees,
// which the walker cannot reach directly.
//
// PathMappings drive two things in handleSymlink:
//
//   - Translation: when a Readlink result is absolute and starts with `From`,
//     that prefix is rewritten to `To` before Stat.
//   - Containment: when at least one mapping is configured, every resolved
//     symlink target (after translation, or the join of dir(symlink)+target
//     for relative targets) must end up under at least one mapping's `To`
//     prefix; otherwise an "out_of_scope_symlink" error is emitted.
//
// An empty PathMappings slice disables both behaviours (no translation, no
// containment) — preserving the legacy behaviour for non-bind-mounted
// deployments.
type PathMapping struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// Options drive a single Walk.
type Options struct {
	// Includes is the list of inclusion patterns. At least one is required.
	Includes []Pattern
	// Excludes is the list of exclusion patterns. An entry matched by any
	// exclude is not produced; a directory matched by an exclude is not
	// descended into (short-circuit).
	Excludes []Pattern
	// FollowSymlinks: if true, symlinks pointing to regular files are
	// produced as entries. The Path remains the symlink path; LinkTo is the
	// resolved target.
	FollowSymlinks bool
	// FollowSymlinkDirs: if true, descend through symlinks pointing to
	// directories. Disabled by default (#469: K8s ..data trick).
	FollowSymlinkDirs bool
	// MaxDepth bounds recursion below the static prefix. Zero means unlimited.
	MaxDepth int
	// FS lets tests inject a fake filesystem; nil means real os.
	FS WalkFS
	// PathMappings declares foreign↔local path-prefix translations and the
	// scope within which symlink targets must remain. See PathMapping for
	// the exact behaviour.
	PathMappings []PathMapping
}

// WalkFS lets tests substitute a fake filesystem.
type WalkFS interface {
	ReadDir(name string) ([]fs.DirEntry, error)
	Lstat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
	Stat(name string) (fs.FileInfo, error)
}

type osFS struct{}

func (osFS) ReadDir(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }
func (osFS) Lstat(name string) (fs.FileInfo, error)     { return os.Lstat(name) }
func (osFS) Readlink(name string) (string, error)       { return os.Readlink(name) }
func (osFS) Stat(name string) (fs.FileInfo, error)      { return os.Stat(name) }

// Walk walks the filesystem with the given options and emits results on the
// returned channel. The channel is closed when the walk completes or the
// context is cancelled.
func Walk(ctx context.Context, opts Options) <-chan Result {
	out := make(chan Result)
	go func() {
		defer close(out)
		fsys := opts.FS
		if fsys == nil {
			fsys = osFS{}
		}
		emit := func(r Result) bool {
			select {
			case <-ctx.Done():
				return false
			case out <- r:
				return true
			}
		}
		// Group includes by their static prefix to avoid descending the
		// same prefix multiple times.
		byPrefix := map[string][]Pattern{}
		var prefixes []string
		for _, p := range opts.Includes {
			if _, ok := byPrefix[p.prefix]; !ok {
				prefixes = append(prefixes, p.prefix)
			}
			byPrefix[p.prefix] = append(byPrefix[p.prefix], p)
		}
		sort.Strings(prefixes)
		for _, pref := range prefixes {
			pats := byPrefix[pref]
			w := &walker{
				fsys: fsys, opts: opts, includes: pats, emit: emit,
			}
			w.descend(ctx, pref, 0, map[uint64]struct{}{})
		}
	}()
	return out
}

type walker struct {
	fsys     WalkFS
	opts     Options
	includes []Pattern
	emit     func(Result) bool
}

// descend walks `dir` matching the remaining segments of every include in w.includes.
func (w *walker) descend(ctx context.Context, dir string, depth int, seenInodes map[uint64]struct{}) {
	if w.opts.MaxDepth > 0 && depth > w.opts.MaxDepth {
		return
	}
	entries, err := w.fsys.ReadDir(dir)
	if err != nil {
		// Report the dir-level error and stop descending here.
		reason := "walk_error"
		if os.IsPermission(err) {
			reason = "permission_denied"
		} else if os.IsNotExist(err) {
			reason = "not_found"
		}
		w.emit(Result{Err: &Error{Path: dir, Reason: reason, Err: err}})
		return
	}
	// Also test whether the dir itself matches an include with empty tail
	// (case where the prefix already pinpoints a file path, no glob tail).
	// Handled by listing entries and matching them below.

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}
		full := path.Join(dir, e.Name())
		if w.excluded(full) {
			continue
		}
		info, err := w.fsys.Lstat(full)
		if err != nil {
			w.emit(Result{Err: &Error{Path: full, Reason: "walk_error", Err: err}})
			continue
		}
		// Determine whether this entry can match any include (file or dir).
		// We classify per-include and act accordingly.
		var fileMatchedPattern *Pattern
		canDescend := false
		for i := range w.includes {
			pat := &w.includes[i]
			leafMatch, dirOK := matchClassify(pat, full)
			if leafMatch && fileMatchedPattern == nil {
				fileMatchedPattern = pat
			}
			if dirOK {
				canDescend = true
			}
		}

		mode := info.Mode()
		switch {
		case mode&os.ModeSymlink != 0:
			w.handleSymlink(ctx, full, info, fileMatchedPattern, canDescend, depth, seenInodes)
		case mode.IsDir():
			if canDescend {
				if k, ok := inodeOf(info); ok {
					if _, dup := seenInodes[k]; dup {
						continue
					}
					seenInodes[k] = struct{}{}
				}
				w.descend(ctx, full, depth+1, seenInodes)
			}
		case mode.IsRegular():
			if fileMatchedPattern != nil {
				w.emit(Result{Entry: Entry{Path: full, Pattern: fileMatchedPattern.raw, Info: info}})
			}
		}
	}
}

func (w *walker) handleSymlink(ctx context.Context, full string, info fs.FileInfo, fileMatched *Pattern, canDescend bool, depth int, seen map[uint64]struct{}) {
	target, err := w.fsys.Readlink(full)
	if err != nil {
		w.emit(Result{Err: &Error{Path: full, Reason: "broken_symlink", Err: err}})
		return
	}
	resolved := target
	if filepath.IsAbs(resolved) {
		// Absolute target: translate through PathMappings if any prefix matches.
		// Otherwise the path is left as-is and the containment check below decides.
		resolved = w.translateAbsoluteTarget(resolved)
	} else {
		// Relative target: anchor at the symlink's parent directory.
		resolved = filepath.Join(filepath.Dir(full), target)
	}
	resolved = filepath.Clean(resolved)

	if !w.inAllowedScope(resolved) {
		w.emit(Result{Err: &Error{
			Path:   full,
			Reason: cert.ReasonOutOfScopeSymlink,
			Err:    fmt.Errorf("resolved target %q is outside any configured scope", resolved),
		}})
		return
	}

	tinfo, err := w.fsys.Stat(resolved)
	if err != nil {
		w.emit(Result{Err: &Error{Path: full, Reason: "broken_symlink", Err: err}})
		return
	}
	if tinfo.IsDir() {
		// We never read a symlink-to-dir as a file (fix #469).
		if w.opts.FollowSymlinkDirs && canDescend {
			if k, ok := inodeOf(tinfo); ok {
				if _, dup := seen[k]; dup {
					return
				}
				seen[k] = struct{}{}
			}
			w.descend(ctx, full, depth+1, seen)
		}
		return
	}
	if tinfo.Mode().IsRegular() && fileMatched != nil && w.opts.FollowSymlinks {
		w.emit(Result{Entry: Entry{
			Path: full, Pattern: fileMatched.raw, Info: info, LinkTo: resolved,
		}})
	}
}

// translateAbsoluteTarget rewrites an absolute path through the longest
// matching PathMapping.From prefix, replacing it with the corresponding
// PathMapping.To. The prefix match is segment-aware: a mapping with
// From="/var" does not match "/var2/foo".
//
// When no mapping matches (or PathMappings is empty), the input is
// returned unchanged. The containment check applied immediately after
// will then decide whether the resulting path is acceptable.
func (w *walker) translateAbsoluteTarget(target string) string {
	if len(w.opts.PathMappings) == 0 {
		return target
	}
	bestFromLen := -1
	var bestTo string
	var bestFrom string
	for _, m := range w.opts.PathMappings {
		from := strings.TrimRight(m.From, "/")
		if from == "" {
			continue
		}
		if !strings.HasPrefix(target, from) {
			continue
		}
		// Boundary check: avoid /var matching /var2/foo.
		if len(target) > len(from) && target[len(from)] != '/' {
			continue
		}
		if len(from) > bestFromLen {
			bestFromLen = len(from)
			bestFrom = from
			bestTo = strings.TrimRight(m.To, "/")
		}
	}
	if bestFromLen < 0 {
		return target
	}
	suffix := target[len(bestFrom):]
	return bestTo + suffix
}

// inAllowedScope returns true iff p (already Clean'd, absolute) is equal to
// or a descendant of one of PathMappings.To prefixes. When PathMappings is
// empty, the scope is unbounded (legacy behaviour).
func (w *walker) inAllowedScope(p string) bool {
	if len(w.opts.PathMappings) == 0 {
		return true
	}
	for _, m := range w.opts.PathMappings {
		to := strings.TrimRight(m.To, "/")
		if to == "" {
			continue
		}
		if p == to || strings.HasPrefix(p, to+"/") {
			return true
		}
	}
	return false
}

// matchClassify returns (leafMatch, descendOK). A leafMatch means the path
// matches the pattern as-is; descendOK means the path is a viable directory
// prefix from which a descendant could still match. Internal: the receiver
// must already be inside the pattern's static prefix.
func matchClassify(p *Pattern, full string) (bool, bool) {
	prefix := strings.TrimRight(p.prefix, "/")
	if prefix == "." || prefix == "" {
		// no static prefix -> consider both modes
		return matchTail(p.segments, splitNonEmpty(full))
	}
	if !strings.HasPrefix(full, prefix) {
		// The walker is responsible for descending only into the prefix;
		// during the descent, all paths share the prefix. If we are
		// outside, neither condition holds.
		// However for sub-entries the path always begins with prefix,
		// so this branch is mostly unreachable defensively.
		return false, strings.HasPrefix(prefix, full+"/")
	}
	tail := strings.TrimPrefix(full, prefix)
	tail = strings.TrimPrefix(tail, "/")
	return matchTail(p.segments, splitNonEmpty(tail))
}

func splitNonEmpty(s string) []string {
	s = strings.Trim(s, "/")
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

// matchTail returns:
//
//	leafMatch: true if the full segment list matches segs entirely
//	descendOK: true if some longer path with extra trailing segments
//	          could still match (i.e., parts is a strict prefix-compatible
//	          sub-sequence of segs).
func matchTail(segs []segment, parts []string) (leaf bool, descend bool) {
	leaf = matchAll(segs, parts)
	descend = canExtend(segs, parts)
	return
}

// canExtend returns true iff there exists at least one suffix of segments
// that could be appended to parts so that the result still matches segs.
// In simple terms: are we still on a path that could lead to a match?
func canExtend(segs []segment, parts []string) bool {
	// We try to consume parts left-to-right, allowing ** to absorb 0+ parts.
	return canExtendRec(segs, 0, parts, 0)
}

func canExtendRec(segs []segment, si int, parts []string, pi int) bool {
	for {
		if pi == len(parts) {
			// Fewer parts than segs (or equal). Remaining segs may be
			// satisfied by future descendants — yes, we can extend.
			return si <= len(segs)
		}
		if si == len(segs) {
			// More parts than segs; the path has overshot the pattern, no
			// extension can make it match.
			return false
		}
		s := segs[si]
		if s.kind == segDoublestar {
			// ** can absorb 0..(len(parts)-pi) parts here, and we may
			// continue with si+1.
			if canExtendRec(segs, si+1, parts, pi) {
				return true
			}
			pi++
			continue
		}
		if !matchSegment(s, parts[pi]) {
			return false
		}
		si++
		pi++
	}
}

func (w *walker) excluded(full string) bool {
	for _, p := range w.opts.Excludes {
		if p.Match(full) {
			return true
		}
	}
	return false
}
