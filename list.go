package main

// viage list: what is in the vault, from the file headers alone, or
// with -v checked against the index.

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

// cmdList lists the vault directory: your files first, then, after a
// blank line, the ones viage keeps for itself (the identity, the index,
// the lock). By default nothing is decrypted and no passphrase is asked
// for; the age header tells a file with its own passphrase from one
// encrypted to a key, but not which key. With -v it unlocks the
// identity, shows the descriptions from the index and checks every file
// against the checksum recorded there.
func cmdList(verbose bool) {
	fi, err := os.Stat(vaultDir)
	if err != nil || !fi.IsDir() {
		die("%s not found (run %s init)", vaultDir, prog)
	}
	if m := looseMode(fi); m != "" {
		warn("warning: %s is open to others (%s); chmod 700 it", vaultDir, m)
	}
	var ix *vaultIndex
	if verbose {
		requireIdentity()
		id := unlock()
		ix, err = loadIndex(id)
		switch {
		case err != nil:
			warn("warning: %v. Descriptions and checksums are not shown.", err)
			ix = nil
		case ix.isNew:
			warn("warning: %s is missing; %s init makes a new one from the vault as it is now.", indexPath(), prog)
			ix = nil
		}
	}
	seen := map[string]bool{}
	var yours, viages []string
	row := func(name, size, date, note string) string {
		return fmt.Sprintf("%-32s %10s  %-12s  %s", name, size, date, note)
	}
	for _, name := range vaultEntries() {
		path := filepath.Join(vaultDir, name)
		fi, err := os.Lstat(path)
		if err != nil {
			continue
		}
		symlink := fi.Mode()&fs.ModeSymlink != 0
		var note string
		own := false
		switch {
		case name == ".lock" && fi.IsDir():
			own = true
			note = prog + "'s lock, held"
			if pid := lockPID(path); pid > 0 {
				note += " by process " + strconv.Itoa(pid)
			}
		case symlink || !fi.Mode().IsRegular():
			note = "not a regular file"
		case sameFile(path, identityPath):
			own = true
			note = prog + "'s key to this vault; keep a backup"
		case newName.MatchString(name):
			note = "unsaved edit; recover or remove it"
		case strings.HasSuffix(name, ".rekey"), strings.HasSuffix(name, ".old"):
			note = "left by an unfinished rekey"
		case stagedName.MatchString(name):
			note = "left by an interrupted " + prog + "; remove it"
		case name == indexName:
			own = true
			note = prog + "'s descriptions and checksums"
			if !verbose {
				note += " (" + prog + " list -v)"
			}
		default:
			switch ageKind(path) {
			case "x25519":
				if sameFile(path, vaultFile) {
					note = "default vault"
				} else if strings.HasSuffix(name, ".age.bak") {
					note = "previous version of " + strings.TrimSuffix(name, ".bak")
				}
				if ix != nil {
					seen[name] = true
					note = indexNote(ix, name, path, note)
				}
			case "scrypt":
				note = "own passphrase; rekey skips it (" + prog + " add brings it in)"
			case "none":
				note = "NOT ENCRYPTED"
			case "damaged":
				note = "damaged age header"
			case "unreadable":
				note = "cannot be read"
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
		if own {
			viages = append(viages, row(name, size, lsDate(fi.ModTime()), note))
		} else {
			yours = append(yours, row(name, size, lsDate(fi.ModTime()), note))
		}
	}
	if ix != nil {
		var missing []string
		for name := range ix.Files {
			if !seen[name] {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		for _, name := range missing {
			if exists(filepath.Join(vaultDir, name)) {
				continue // there, but not encrypted to a key; flagged above
			}
			yours = append(yours, row(name, "-", "-", "MISSING: in the index, not in the vault"))
		}
	}
	for _, l := range yours {
		fmt.Println(l)
	}
	if len(yours) > 0 && len(viages) > 0 {
		fmt.Println()
	}
	for _, l := range viages {
		fmt.Println(l)
	}
}

// indexNote is the -v note for a vault file: its description, or the
// label it would have had, and whether it matches the index.
func indexNote(ix *vaultIndex, name, path, label string) string {
	m := ix.Files[name]
	if m == nil {
		return join(label, "not in the index ("+prog+" add brings it in)")
	}
	if m.Description != "" {
		label = m.Description
	}
	ct, err := os.ReadFile(path)
	if err != nil || checksum(ct) != m.SHA256 {
		return join(label, "CHANGED OUTSIDE "+strings.ToUpper(prog)+"; check it with "+prog+" cat")
	}
	return label
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// lsDate formats a time the way ls -l does: the time of day for the
// last six months, the year before that.
func lsDate(t time.Time) string {
	if time.Since(t) < 182*24*time.Hour && time.Until(t) < time.Hour {
		return t.Format("Jan 2 15:04")
	}
	return t.Format("Jan 2 2006")
}
