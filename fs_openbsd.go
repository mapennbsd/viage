package main

import "golang.org/x/sys/unix"

func fsTypeOf(st *unix.Statfs_t) string {
	return cstring(st.F_fstypename[:])
}
