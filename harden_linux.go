package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// harden keeps plaintext and the identity out of core files, and makes
// this process's memory unreadable to other processes running as the
// same user: a non-dumpable process cannot be traced, and its /proc
// files belong to root. Children (the editor) inherit the core limit
// but not the dumpable flag, which exec resets. Either failing is fatal,
// before any passphrase is asked for.
func harden() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("cannot turn off core dumps: %v", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("cannot make this process non-dumpable: %v", err)
	}
	return nil
}
