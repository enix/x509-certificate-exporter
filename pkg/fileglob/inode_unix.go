//go:build unix

package fileglob

import (
	"io/fs"
	"syscall"
)

// inodeOf returns a (dev,ino) packed key for cycle detection. It returns
// false when the platform-specific stat info is not available (e.g., a
// fake FS used in tests), in which case the caller falls back to no
// cycle detection.
func inodeOf(info fs.FileInfo) (uint64, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	// Conversions kept for cross-platform: on Darwin/BSD st.Dev is int32.
	return uint64(st.Dev)<<32 | uint64(st.Ino), true //nolint:unconvert
}
