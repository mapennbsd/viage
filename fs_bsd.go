//go:build freebsd || darwin || dragonfly

package main

import "golang.org/x/sys/unix"

func fsTypeOf(st *unix.Statfs_t) string {
	return cstring(st.Fstypename[:])
}
