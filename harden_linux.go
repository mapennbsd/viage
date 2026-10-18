package main

import "golang.org/x/sys/unix"

// harden keeps plaintext and the identity out of core files, and makes
// this process's memory unreadable to other processes running as the
// same user: a non-dumpable process cannot be traced, and its /proc
// files belong to root. Children (the editor) inherit the core limit
// but not the dumpable flag, which exec resets.
func harden() {
	unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{})
	unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
