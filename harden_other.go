//go:build !linux

package main

import "golang.org/x/sys/unix"

// harden keeps plaintext and the identity out of core files. Children
// (the editor) inherit the limit.
func harden() {
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
}
