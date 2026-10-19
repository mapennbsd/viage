//go:build !linux

package main

// Hardening the process on systems other than Linux: no core dumps.

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// harden keeps plaintext and the identity out of core files. Children
// (the editor) inherit the limit. Failing is fatal, before any
// passphrase is asked for.
func harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("cannot turn off core dumps: %v", err)
	}
	return nil
}
