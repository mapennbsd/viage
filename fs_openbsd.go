package main

// The filesystem type on OpenBSD, from statfs's type name.

import "golang.org/x/sys/unix"

func fsTypeOf(st *unix.Statfs_t) string {
	return cstring(st.F_fstypename[:])
}
