package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

func removeRekeyFiles() {
	os.Remove(identityPath + ".rekey")
	if des, err := os.ReadDir(vaultDir); err == nil {
		for _, de := range des {
			if strings.HasSuffix(de.Name(), ".rekey") {
				os.Remove(filepath.Join(vaultDir, de.Name()))
			}
		}
	}
}

type rekeyItem struct {
	path        string
	orig, plain []byte
}

// cmdRekey replaces the identity with a new one under a new passphrase
// and re-encrypts the vault to it. The old identity is deleted at the
// end, so rekey must leave nothing behind that only the old identity
// opens. It looks at every file in the vault directory, by what is in
// it rather than by its name, and stops before changing anything at
// whatever it cannot account for: a file it cannot read, a symlink, a
// subdirectory holding age files, a file with other hard links, a
// default vault that is not directly in the vault directory, leftovers
// of an earlier run. Every file encrypted to the identity must be in
// the index and match it, so that changing the passphrase never quietly
// accepts a file changed outside viage. Files encrypted to anything
// else are skipped with a warning; the old identity does not open them
// either. Everything is written and checked before anything is renamed
// into place. Copies of the old identity elsewhere (snapshots, backups)
// still open the files as they were before.
func cmdRekey() {
	checkWritable()
	requireIdentity()
	lockVault()
	for _, f := range []string{identityPath + ".old", identityPath + ".rekey"} {
		if exists(f) {
			die("%s exists; a previous rekey did not finish", f)
		}
	}
	var paths []string
	for _, name := range vaultEntries() {
		path := filepath.Join(vaultDir, name)
		fi, err := os.Lstat(path)
		if err != nil {
			die("cannot read %s: %v; nothing changed", path, err)
		}
		switch {
		case name == ".lock" && fi.IsDir(), sameEntry(path, identityPath):
			continue
		case strings.HasSuffix(name, ".rekey"):
			die("%s exists; a previous rekey did not finish", path)
		case newName.MatchString(name):
			die("%s holds an unsaved edit; recover or remove it first", path)
		case stagedName.MatchString(name):
			die("%s was left by an interrupted %s; remove it first", path, prog)
		case fi.Mode()&fs.ModeSymlink != 0:
			die("%s is a symlink, which rekey does not follow; replace it with the file, or move it out of %s", path, vaultDir)
		case fi.IsDir():
			nested, err := findAgeFile(path)
			if err != nil {
				die("%v, and rekey must see every file before it replaces the identity; nothing changed", err)
			}
			if nested != "" {
				die("%s is in a subdirectory, which rekey does not cover; move it into %s or out of it", nested, vaultDir)
			}
			continue
		case !fi.Mode().IsRegular() || name == indexName:
			continue
		}
		switch ageKind(path) {
		case "x25519":
			if n := links(path); n > 1 {
				die("%s has %d other hard links, which rekey would leave encrypted to the old identity; nothing changed", path, n-1)
			}
			paths = append(paths, path)
		case "unreadable":
			die("cannot read %s, and rekey must see every file before it replaces the identity; nothing changed", path)
		case "scrypt":
			warn("skipping %s: it has its own passphrase (%s add brings it in)", path, prog)
		case "none":
			warn("skipping %s: it is not age-encrypted", path)
		case "damaged":
			warn("skipping %s: its age header is damaged", path)
		default:
			warn("skipping %s: it is encrypted to another kind of key", path)
		}
	}
	// The default vault must be one of them, however VIAGE_FILE names it.
	switch fi, err := os.Stat(vaultFile); {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		die("cannot read %s: %v; nothing changed", vaultFile, err)
	case err == nil && fi.Mode().IsRegular() && !slices.ContainsFunc(paths, func(p string) bool { return sameEntry(vaultFile, p) }):
		if k := ageKind(vaultFile); k == "x25519" || k == "unreadable" {
			die("%s, the default vault, is not directly in %s, which is all rekey covers; nothing changed", vaultFile, vaultDir)
		}
	}
	if len(paths) == 0 {
		die("no vault files in %s", vaultDir)
	}

	id := unlock()
	ix := mustLoadIndex(id, "nothing changed")
	var items []rekeyItem
	var problems []string
	for _, p := range paths {
		orig, err := os.ReadFile(p)
		if err != nil {
			die("cannot read %s: %v; nothing changed", p, err)
		}
		plain, err := decrypt(orig, id)
		switch {
		case notOurs(err):
			warn("skipping %s: it does not decrypt with this identity", p)
			continue
		case err != nil:
			die("%s is encrypted to this identity but does not decrypt: %v; nothing changed", p, err)
		}
		switch m := ix.Files[filepath.Base(p)]; {
		case m == nil:
			problems = append(problems, fmt.Sprintf("%s is not in the index; check it with %s cat, then %s add %s brings it in", p, prog, prog, p))
		case m.SHA256 != checksum(orig):
			problems = append(problems, fmt.Sprintf("%s changed outside %s; check it with %s cat, then %s add %s takes it as it is", p, prog, prog, prog, p))
		}
		items = append(items, rekeyItem{p, orig, plain})
	}
	var gone []string
	for name := range ix.Files {
		path := filepath.Join(vaultDir, name)
		switch {
		case !exists(path):
			gone = append(gone, name)
		case !slices.ContainsFunc(items, func(it rekeyItem) bool { return it.path == path }):
			problems = append(problems, fmt.Sprintf("%s changed outside %s: it is in the index, but no longer encrypted to this identity", path, prog))
		}
	}
	for _, pr := range problems {
		warn("%s", pr)
	}
	if len(problems) > 0 {
		die("nothing changed")
	}
	if len(items) == 0 {
		die("nothing in %s decrypts with this identity; nothing changed", vaultDir)
	}
	sort.Strings(gone)
	for _, name := range gone {
		warn("%s is in the index but not in %s; dropping it. A copy kept\n"+
			"elsewhere opens only with the old identity.", name, vaultDir)
		delete(ix.Files, name)
	}

	os.Stderr.WriteString("Choose the new vault passphrase.\n")
	newID, idFile := newIdentity("nothing changed")

	// Write and check everything beside the originals first.
	setRekeying("writing")
	publishOver(stage(idFile, identityPath), identityPath+".rekey")
	for _, it := range items {
		ct := sealTo(it.plain, newID)
		publishOver(stage(ct, it.path), it.path+".rekey")
		if now, err := os.ReadFile(it.path); err != nil || !bytes.Equal(now, it.orig) {
			die("%s changed during the rekey; nothing changed", it.path)
		}
		ix.Files[filepath.Base(it.path)].SHA256 = checksum(ct)
	}
	// The index goes with the files, authenticated by the new identity.
	publishOver(stage(ix.seal(newID), indexPath()), indexPath()+".rekey")

	// The identity goes first and the old one is kept until every file
	// is in place and on disk, so an interruption or a failing disk
	// leaves something recoverable. Signals are ignored from here on.
	setRekeying("committing")
	mustRename(identityPath, identityPath+".old")
	mustRename(identityPath+".rekey", identityPath)
	for _, it := range items {
		mustRename(it.path+".rekey", it.path)
	}
	mustRename(indexPath()+".rekey", indexPath())
	if err := errors.Join(syncDir(filepath.Dir(identityPath)), syncDir(vaultDir)); err != nil {
		setRekeying("")
		die("every file is renamed into place, but flushing them to disk failed: %v. The old identity stays in %s.old until the disk is known to be good", err, identityPath)
	}
	os.Remove(identityPath + ".old")
	if err := syncDir(filepath.Dir(identityPath)); err != nil {
		warn("warning: flushing %s failed: %v", filepath.Dir(identityPath), err)
	}
	setRekeying("")

	for _, it := range items {
		warn("rekeyed %s", shown(it.path))
	}
	warn("new identity in %s. Update every copy of the passphrase\n"+
		"and of %s kept elsewhere. Older copies of the identity,\n"+
		"in snapshots and backups, still open these files as they were before\n"+
		"now; rotate the secrets themselves if the old passphrase may be known.",
		identityPath, filepath.Base(identityPath))
}

func mustRename(from, to string) {
	if err := os.Rename(from, to); err != nil {
		die("cannot rename %s to %s: %v", from, to, err)
	}
}

// findAgeFile returns a file under dir that may be encrypted to the
// identity, by its name or by what is in it, or "". A directory or file
// it cannot read is an error: it might hold one.
func findAgeFile(dir string) (string, error) {
	found := ""
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			return nil
		case isVaultName(d.Name()):
			found = p
		case d.Type().IsRegular():
			switch ageKind(p) {
			case "x25519":
				found = p
			case "unreadable":
				return fmt.Errorf("cannot read %s", p)
			}
		}
		if found != "" {
			return filepath.SkipAll
		}
		return nil
	})
	return found, err
}
