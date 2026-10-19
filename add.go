package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

// addDest is the vault file that add writes for src.
func addDest(src string) string {
	b := filepath.Base(src)
	if !strings.HasSuffix(b, ".age") {
		b += ".age"
	}
	return filepath.Join(vaultDir, b)
}

// sameEntry is true when a and b are one directory entry, not merely
// two names (hard links) for one file.
func sameEntry(a, b string) bool {
	return filepath.Base(a) == filepath.Base(b) && sameFile(filepath.Dir(a), filepath.Dir(b)) && sameFile(a, b)
}

// links is the number of hard links to path, or 0.
func links(path string) uint64 {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil {
		return 0
	}
	return uint64(st.Nlink)
}

func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

type addItem struct {
	src, dest   string
	orig, plain []byte
	imported    bool // the source was already age-encrypted
	inPlace     bool // the source is its own destination
	skip        bool // already encrypted to the identity, in place
}

// cmdAdd encrypts files into the vault and removes the originals (-k
// keeps them). A file that is already age-encrypted, with its own
// passphrase or to the identity, is decrypted and re-encrypted to the
// identity; that is how an out-of-band file comes under viage, in place
// if it is in the vault directory. Every file is read and decrypted, in
// memory, before anything is written.
func cmdAdd(args []string) {
	keep, describe := false, ""
flags:
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch {
		case args[0] == "-k":
			keep = true
			args = args[1:]
		case args[0] == "-m" && len(args) > 1:
			describe = strings.TrimSpace(args[1])
			args = args[2:]
		case args[0] == "--":
			args = args[1:]
			break flags
		default:
			usageError()
		}
	}
	if len(args) == 0 {
		usageError()
	}
	checkWritable()
	requireIdentity()
	lockVault()
	seen := map[string]bool{}
	for _, f := range args {
		fi, err := os.Lstat(f)
		// Removing a link would leave the plaintext it points to.
		if err == nil && fi.Mode()&fs.ModeSymlink != 0 {
			die("%s is a symlink; add the file it points to", f)
		}
		if err != nil || !fi.Mode().IsRegular() || unix.Access(f, unix.R_OK) != nil {
			die("%s is not a readable file", f)
		}
		if sameFile(f, identityPath) {
			die("%s is the identity", f)
		}
		dest := addDest(f)
		if filepath.Base(dest) == indexName {
			die("%s is the name of the index; rename the file first", indexName)
		}
		// Another name for the destination is not the destination: a
		// hard link outside the vault would keep the plaintext.
		if exists(dest) && !sameEntry(f, dest) {
			die("%s exists", dest)
		}
		if seen[dest] {
			die("two files would be added as %s", dest)
		}
		seen[dest] = true
	}

	id := unlock()
	ix := mustLoadIndex(id, "nothing added")
	var items []addItem
	for _, f := range args {
		orig, err := os.ReadFile(f)
		if err != nil {
			die("cannot read %s: %v; nothing added", f, err)
		}
		it := addItem{src: f, dest: addDest(f), orig: orig, inPlace: sameEntry(f, addDest(f))}
		switch ageKind(f) {
		case "none":
			// Removing or replacing one name leaves the plaintext in
			// the others.
			if n := links(f); n > 1 && (it.inPlace || !keep) {
				die("%s has %d other hard links, which would keep the plaintext; remove them first; nothing added", f, n-1)
			}
			it.plain = orig
		case "unreadable":
			die("cannot read %s; nothing added", f)
		case "scrypt":
			warn("%s has a passphrase of its own; enter it to bring the file in.", f)
			p := readPassphrase(fmt.Sprintf("Enter passphrase for \"%s\": ", f))
			sid, err := age.NewScryptIdentity(p)
			if err == nil {
				it.plain, err = decrypt(orig, sid)
			}
			if err != nil {
				die("cannot decrypt %s; nothing added", f)
			}
			it.imported = true
		case "damaged":
			die("the age header of %s cannot be read; nothing added", f)
		default:
			it.plain, err = decrypt(orig, id)
			if err != nil {
				die("%s is encrypted to another key; nothing added", f)
			}
			it.imported = true
			it.skip = it.inPlace
		}
		items = append(items, it)
	}

	for _, it := range items {
		name := filepath.Base(it.dest)
		if it.skip {
			if m := ix.Files[name]; m != nil && m.SHA256 == checksum(it.orig) && (describe == "" || m.Description == describe) {
				warn("%s is already in the vault", shown(it.dest))
				continue
			}
			ix.record(name, it.orig)
			if describe != "" {
				ix.Files[name].Description = describe
			}
			ix.save(id)
			warn("%s is already in the vault; recorded it in the index", shown(it.dest))
			continue
		}
		exposed := !it.imported && !isRAM(it.src)
		ct := sealTo(it.plain, id)
		staged := stage(ct, it.dest)
		if it.inPlace {
			publishOver(staged, it.dest)
		} else {
			publishNew(staged, it.dest)
		}
		ix.record(name, ct)
		if describe != "" {
			ix.Files[name].Description = describe
		}
		ix.save(id)
		if it.inPlace {
			warn("re-encrypted %s to the vault identity", shown(it.dest))
			continue
		}
		switch now, err := os.ReadFile(it.src); {
		case keep:
			warn("added %s; kept %s", shown(it.dest), it.src)
		case err != nil || !bytes.Equal(now, it.orig):
			warn("added %s; kept %s, which changed while it was being added", shown(it.dest), it.src)
		case os.Remove(it.src) != nil:
			warn("added %s; could not remove %s", shown(it.dest), it.src)
		default:
			warn("added %s; removed %s", shown(it.dest), it.src)
		}
		if exposed {
			warn("warning: %s was plaintext on persistent storage. Deleting it does\n"+
				"not reach the snapshots and backups that already copied it.", it.src)
		}
	}
}
