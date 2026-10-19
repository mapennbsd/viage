package main

// Messages and exiting; what viage puts right on the way out (the
// terminal, staged files, an unfinished rekey, the plaintext directory,
// the vault lock); and signals, passed on to the editor while it runs.

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

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
	committing bool        // ignore signals: rekey is renaming files into place
	editing    bool        // ignore ^C and ^\: they are meant for the editor
	editor     *os.Process // the editor, while it runs
	stopping   os.Signal   // a HUP or TERM that arrived while it ran
)

// warn prints a message as "viage: message". The lines of a longer
// message are lined up under the first, so it reads as one.
func warn(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	msg = strings.ReplaceAll(msg, "\n", "\n"+strings.Repeat(" ", len(prog)+2))
	fmt.Fprintf(os.Stderr, "%s: %s\n", prog, msg)
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
		warn("rekey interrupted while renaming files into place.\n"+
			"The old identity is %s.old. Files still named *.rekey\n"+
			"are encrypted to the new identity; rename them over the originals.\n"+
			"The vault stays locked until then; afterwards remove %s.", identityPath, lockDir)
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
			// The editor holds the plaintext open and needs the lock
			// to be saved, so viage stops it and waits for it to exit
			// before tidying up. See stopEditor.
			if editing {
				if stopping == nil {
					stopping = sig
					stopEditor()
				}
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

// setEditor records the running editor, and stops it at once if a
// signal came while it was being started.
func setEditor(p *os.Process) {
	mu.Lock()
	defer mu.Unlock()
	editor = p
	if p != nil && stopping != nil {
		stopEditor()
	}
}

// stopEditor, with mu held, passes the signal on to the editor, and
// kills it if it is still running five seconds later.
func stopEditor() {
	if editor == nil {
		return
	}
	p := editor
	p.Signal(stopping)
	time.AfterFunc(5*time.Second, func() { p.Kill() })
}

// editorStopped is the signal that stopped the edit, if any.
func editorStopped() os.Signal {
	mu.Lock()
	defer mu.Unlock()
	return stopping
}
