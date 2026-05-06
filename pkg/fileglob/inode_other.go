//go:build !unix

package fileglob

import "io/fs"

func inodeOf(_ fs.FileInfo) (uint64, bool) { return 0, false }
