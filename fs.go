//go:build linux || freebsd || darwin || dragonfly || openbsd

package main

// Telling a RAM-backed filesystem from one on disk, by the type of the
// filesystem under a path or an open file. The per-system part is in
// fs_<system>.go.

import "golang.org/x/sys/unix"

// fsType returns the type of the filesystem holding path: "tmpfs",
// "ramfs" or "mfs" for the RAM-backed ones, something else otherwise,
// or "" if it cannot be told.
func fsType(path string) string {
	var st unix.Statfs_t
	if unix.Statfs(path, &st) != nil {
		return ""
	}
	return fsTypeOf(&st)
}

// fdFSType is fsType for an open file descriptor.
func fdFSType(fd int) string {
	var st unix.Statfs_t
	if unix.Fstatfs(fd, &st) != nil {
		return ""
	}
	return fsTypeOf(&st)
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
