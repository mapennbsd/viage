package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
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
// and re-encrypts every vault file to it: each *.age and *.age.bak
// directly in the vault directory, hidden ones included. Anything rekey
// cannot cover (a vault file in a subdirectory or behind a symlink, the
// default vault outside the vault directory) stops it before it starts,
// since the old identity is deleted at the end. Files that are not
// encrypted to the identity are skipped with a warning. Everything is
// written and checked before anything is renamed into place. Copies of
// the old identity elsewhere (snapshots, backups) still open the files
// as they were before.
func cmdRekey() {
	checkWritable()
	requireIdentity()
	lockVault()
	if !strings.HasPrefix(vaultFile, vaultDir+"/") {
		if fi, err := os.Stat(vaultFile); err == nil && fi.Mode().IsRegular() {
			die("%s is outside %s; rekey works on %s only", vaultFile, vaultDir, vaultDir)
		}
	}
	for _, f := range []string{identityPath + ".old", identityPath + ".rekey"} {
		if exists(f) {
			die("%s exists; a previous rekey did not finish", f)
		}
	}
	var paths []string
	for _, name := range vaultEntries() {
		path := filepath.Join(vaultDir, name)
		fi, err := os.Lstat(path)
		if err != nil || name == ".lock" {
			continue
		}
		switch {
		case strings.HasSuffix(name, ".rekey"):
			die("%s exists; a previous rekey did not finish", path)
		case strings.Contains(name, ".new."):
			die("%s holds an unsaved edit; recover or remove it first", path)
		case fi.IsDir():
			if nested := findVaultFile(path); nested != "" {
				die("%s is in a subdirectory, which rekey does not cover; move it into %s or out of it", nested, vaultDir)
			}
			continue
		}
		if !strings.HasSuffix(name, ".age") && !strings.HasSuffix(name, ".age.bak") {
			continue
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			die("%s is a symlink, which rekey does not follow; replace it with the file", path)
		}
		if !fi.Mode().IsRegular() || sameFile(path, identityPath) {
			continue
		}
		switch ageKind(path) {
		case "x25519":
			paths = append(paths, path)
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
	if len(paths) == 0 {
		die("no vault files in %s", vaultDir)
	}

	id := unlock()
	var items []rekeyItem
	for _, p := range paths {
		orig, err := os.ReadFile(p)
		if err != nil {
			die("cannot read %s: %v; nothing changed", p, err)
		}
		plain, err := decrypt(orig, id)
		if err != nil {
			warn("skipping %s: it does not decrypt with this identity", p)
			continue
		}
		items = append(items, rekeyItem{p, orig, plain})
	}
	if len(items) == 0 {
		die("nothing in %s decrypts with this identity; nothing changed", vaultDir)
	}

	os.Stderr.WriteString("Choose the new vault passphrase.\n")
	newID, idFile := newIdentity("nothing changed")

	// Write and check everything beside the originals first.
	setRekeying("writing")
	publishOver(stage(idFile, identityPath), identityPath+".rekey")
	for _, it := range items {
		publishOver(stage(sealTo(it.plain, newID), it.path), it.path+".rekey")
		if now, err := os.ReadFile(it.path); err != nil || !bytes.Equal(now, it.orig) {
			die("%s changed during the rekey; nothing changed", it.path)
		}
	}

	// The identity goes first and the old one is kept until every file
	// is in place, so an interruption leaves something recoverable.
	// Signals are ignored from here on.
	setRekeying("committing")
	mustRename(identityPath, identityPath+".old")
	mustRename(identityPath+".rekey", identityPath)
	for _, it := range items {
		mustRename(it.path+".rekey", it.path)
	}
	syncDir(filepath.Dir(identityPath))
	syncDir(vaultDir)
	os.Remove(identityPath + ".old")
	syncDir(filepath.Dir(identityPath))
	setRekeying("")

	for _, it := range items {
		warn("rekeyed %s", it.path)
	}
	warn("new identity in %s. Update every copy of the passphrase", identityPath)
	warn("and of %s kept elsewhere. Older copies of the identity,", filepath.Base(identityPath))
	warn("in snapshots and backups, still open these files as they were before")
	warn("now; rotate the secrets themselves if the old passphrase may be known.")
}

func mustRename(from, to string) {
	if err := os.Rename(from, to); err != nil {
		die("cannot rename %s to %s: %v", from, to, err)
	}
}

// findVaultFile returns a vault file somewhere under dir, or "".
func findVaultFile(dir string) string {
	found := ""
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && (strings.HasSuffix(p, ".age") || strings.HasSuffix(p, ".age.bak")) {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	return found
}
