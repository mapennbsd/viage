//go:build freebsd || darwin || dragonfly

package main

// The filesystem type on FreeBSD, DragonFly and macOS, from statfs's
// type name.

import "golang.org/x/sys/unix"

func fsTypeOf(st *unix.Statfs_t) string {
	return cstring(st.Fstypename[:])
}
