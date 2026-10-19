package main

// The filesystem type on Linux, from statfs's magic number.

import "golang.org/x/sys/unix"

func fsTypeOf(st *unix.Statfs_t) string {
	switch uint32(st.Type) {
	case unix.TMPFS_MAGIC:
		return "tmpfs"
	case unix.RAMFS_MAGIC:
		return "ramfs"
	}
	return "other"
}
