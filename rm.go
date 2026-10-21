package main

// viage rm: removing files from the vault, and from the index.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// cmdRm removes vault files and their entries in the index. Removing
// name.age also removes its backup, name.age.bak; a backup can be
// removed on its own. A name that is in the index but no longer in the
// vault has just its entry dropped, which is how a file deleted outside
// viage stops showing as MISSING. The identity, the index and the
// default vault are refused, and every name is checked before anything
// is removed. The passphrase is needed because only the identity can
// write an index that verifies. Copies in snapshots and backups still
// open with the identity; rekey is what puts them out of reach.
func cmdRm(args []string) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	} else if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		usageError()
	}
	if len(args) == 0 {
		usageError()
	}
	checkWritable()
	requireIdentity()
	lockVault()
	var names []string
	seen := map[string]bool{}
	implied := map[string]bool{} // backups not named, only implied
	for _, a := range args {
		path := resolve(a)
		name := inVault(path)
		switch {
		case name == "" || name == indexName || leftover(name) || sameFile(path, identityPath):
			die("%s is not a file in %s", path, vaultDir)
		case filepath.Clean(path) == filepath.Clean(vaultFile) || sameFile(path, vaultFile):
			die("%s is the default vault ($VIAGE_FILE); nothing removed", shown(path))
		}
		// The backup goes with the file it is a backup of.
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
		delete(implied, name)
		if bak := name + ".bak"; !strings.HasSuffix(name, ".bak") && !seen[bak] {
			seen[bak] = true
			implied[bak] = true
			names = append(names, bak)
		}
	}
	for _, n := range names {
		if fi, err := os.Lstat(filepath.Join(vaultDir, n)); err == nil && !fi.Mode().IsRegular() {
			die("%s is not a regular file; nothing removed", n)
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			die("cannot read %s: %v; nothing removed", n, err)
		}
	}

	id := unlock()
	ix := mustLoadIndex(id, "nothing removed")
	type target struct {
		name             string
		present, indexed bool
	}
	var targets []target
	for _, n := range names {
		t := target{name: n, present: exists(filepath.Join(vaultDir, n)), indexed: ix.Files[n] != nil}
		// An implied backup may not exist; a name asked for must be in
		// the vault or in the index.
		if !t.present && !t.indexed {
			if implied[n] {
				continue
			}
			die("%s not found (see %s list); nothing removed", n, prog)
		}
		targets = append(targets, t)
	}

	removed := false
	for _, t := range targets {
		if t.present {
			if err := os.Remove(filepath.Join(vaultDir, t.name)); err != nil {
				ix.save(id)
				die("cannot remove %s: %v", t.name, err)
			}
			removed = true
		}
		delete(ix.Files, t.name)
	}
	if removed {
		mustSyncDir(vaultDir)
	}
	ix.save(id)
	for _, t := range targets {
		switch {
		case !t.present:
			warn("dropped %s from the index; the file was already gone", t.name)
		case !t.indexed:
			warn("removed %s, which was not in the index", t.name)
		default:
			warn("removed %s", t.name)
		}
	}
	if removed {
		warn("copies in snapshots and backups still open with this identity;\n"+
			"%s rekey replaces it, after which they need the old one.", prog)
	}
}
