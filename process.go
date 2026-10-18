package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"golang.org/x/term"
)

// Everything that must be undone on exit, however viage exits. It is
// guarded by mu because a signal can arrive at any point; cleanup runs
// once, with mu held, and the process ends.
var (
	mu         sync.Mutex
	tmpDir     string              // private RAM-backed directory
	partials   = map[string]bool{} // staged files not yet renamed into place
	rekeying   string              // "", "writing" or "committing"
	lockDir    string              // the vault lock, while held
	termFd     = -1                // a terminal whose state to restore
	termState  *term.State
	committing bool // ignore signals: rekey is renaming files into place
	editing    bool // ignore ^C and ^\: they are meant for the editor
)

func warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, prog+": "+format+"\n", a...)
}

func die(format string, a ...any) {
	warn(format, a...)
	exit(1)
}

func exit(code int) {
	mu.Lock()
	cleanup()
	os.Exit(code)
}

// cleanup runs with mu held. The lock goes last, so that nothing else
// writes the vault while it is being tidied.
func cleanup() {
	if termState != nil {
		term.Restore(termFd, termState)
		termState = nil
	}
	for p := range partials {
		os.Remove(p)
	}
	partials = map[string]bool{}
	switch rekeying {
	case "writing":
		removeRekeyFiles()
	case "committing":
		warn("rekey interrupted while renaming files into place.")
		warn("The old identity is %s.old. Files still named *.rekey", identityPath)
		warn("are encrypted to the new identity; rename them over the originals.")
		warn("The vault stays locked until then; afterwards remove %s.", lockDir)
		lockDir = ""
	}
	rekeying = ""
	if tmpDir != "" {
		os.RemoveAll(tmpDir)
		tmpDir = ""
	}
	if lockDir != "" {
		os.RemoveAll(lockDir)
		lockDir = ""
	}
}

func handleSignals() {
	c := make(chan os.Signal, 4)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	go func() {
		for s := range c {
			sig := s.(syscall.Signal)
			mu.Lock()
			if committing || (editing && (sig == syscall.SIGINT || sig == syscall.SIGQUIT)) {
				mu.Unlock()
				continue
			}
			cleanup()
			os.Exit(128 + int(sig))
		}
	}()
}

func setPartial(p string, on bool) {
	mu.Lock()
	defer mu.Unlock()
	if on {
		partials[p] = true
	} else {
		delete(partials, p)
	}
}

func setRekeying(state string) {
	mu.Lock()
	defer mu.Unlock()
	rekeying = state
	committing = state == "committing"
}

func setEditing(on bool) {
	mu.Lock()
	defer mu.Unlock()
	editing = on
}
