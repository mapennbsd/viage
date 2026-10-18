package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// vaultEntries lists the vault directory, ordinary names first, then
// hidden ones, as ls -A would group them.
func vaultEntries() []string {
	des, err := os.ReadDir(vaultDir)
	if err != nil {
		die("%s not found (run %s init)", vaultDir, prog)
	}
	var names []string
	for _, de := range des {
		names = append(names, de.Name())
	}
	sort.SliceStable(names, func(i, j int) bool {
		hi, hj := strings.HasPrefix(names[i], "."), strings.HasPrefix(names[j], ".")
		if hi != hj {
			return hj
		}
		return names[i] < names[j]
	})
	return names
}

// A file left by a viage that was stopped while writing (see stage).
var stagedName = regexp.MustCompile(`^\..*\.age(\.bak)?\.[A-Za-z0-9]{6}$`)

// cmdList lists the vault directory. Nothing is decrypted and no
// passphrase is asked for; the age header tells a file with its own
// passphrase from one encrypted to a key, but not which key.
func cmdList() {
	fi, err := os.Stat(vaultDir)
	if err != nil || !fi.IsDir() {
		die("%s not found (run %s init)", vaultDir, prog)
	}
	if m := looseMode(fi); m != "" {
		warn("warning: %s is open to others (%s); chmod 700 it", vaultDir, m)
	}
	for _, name := range vaultEntries() {
		path := filepath.Join(vaultDir, name)
		fi, err := os.Lstat(path)
		if err != nil {
			continue
		}
		symlink := fi.Mode()&fs.ModeSymlink != 0
		var note string
		switch {
		case name == ".lock" && fi.IsDir():
			note = "lock held"
			if pid := lockPID(path); pid > 0 {
				note += " by process " + strconv.Itoa(pid)
			}
		case symlink || !fi.Mode().IsRegular():
			note = "not a regular file"
		case sameFile(path, identityPath):
			note = "identity"
		case strings.Contains(name, ".new."):
			note = "unsaved edit; recover or remove it"
		case strings.HasSuffix(name, ".rekey"), strings.HasSuffix(name, ".old"):
			note = "left by an unfinished rekey"
		case stagedName.MatchString(name):
			note = "left by an interrupted " + prog + "; remove it"
		default:
			switch ageKind(path) {
			case "x25519":
				if sameFile(path, vaultFile) {
					note = "default vault"
				} else if strings.HasSuffix(name, ".age.bak") {
					note = "previous version of " + strings.TrimSuffix(name, ".bak")
				}
			case "scrypt":
				note = "own passphrase; rekey skips it (" + prog + " add brings it in)"
			case "none":
				note = "NOT ENCRYPTED"
			case "damaged":
				note = "damaged age header"
			default:
				note = "another kind of key; rekey skips it"
			}
		}
		if m := looseMode(fi); m != "" && !symlink {
			if note != "" {
				note += "; "
			}
			note += "open to others (" + m + ")"
		}
		size := "-"
		if !symlink && fi.Mode().IsRegular() {
			size = strconv.FormatInt(fi.Size(), 10)
		}
		fmt.Printf("%-32s %10s  %-12s  %s\n", name, size, lsDate(fi.ModTime()), note)
	}
}

// lsDate formats a time the way ls -l does: the time of day for the
// last six months, the year before that.
func lsDate(t time.Time) string {
	if time.Since(t) < 182*24*time.Hour && time.Until(t) < time.Hour {
		return t.Format("Jan 2 15:04")
	}
	return t.Format("Jan 2 2006")
}
