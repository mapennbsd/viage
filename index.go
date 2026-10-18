package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// The index, index.age, holds a description and the SHA-256 of the
// ciphertext of each file in the vault, so that list -v can say what a
// file is and notice one that was replaced by anything but viage. It is
// encrypted to the identity like everything else, and it carries an
// HMAC keyed from the identity: age encryption proves nothing about who
// wrote a file, since anyone who knows the public key can encrypt to
// it, but only the holder of the identity can produce an index that
// verifies. It cannot detect the whole vault, index included, being
// rolled back to an older copy.
const indexName = "index.age"

type fileMeta struct {
	Description string `json:"description,omitempty"`
	Added       string `json:"added,omitempty"`
	Updated     string `json:"updated,omitempty"`
	SHA256      string `json:"sha256"`
}

type vaultIndex struct {
	Files map[string]*fileMeta `json:"files"`
	MAC   string               `json:"mac"`
	isNew bool
}

func indexPath() string { return filepath.Join(vaultDir, indexName) }

// inVault returns the name of path in the vault directory, or "" if it
// is not directly in it.
func inVault(path string) string {
	if filepath.Dir(path) != filepath.Clean(vaultDir) {
		return ""
	}
	return filepath.Base(path)
}

func indexMAC(files map[string]*fileMeta, id *age.X25519Identity) string {
	key := sha256.Sum256([]byte("viage index v1\n" + id.String()))
	b, _ := json.Marshal(files) // map keys are sorted, so this is stable
	m := hmac.New(sha256.New, key[:])
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func checksum(ciphertext []byte) string {
	s := sha256.Sum256(ciphertext)
	return hex.EncodeToString(s[:])
}

// loadIndex reads and verifies the index. A missing index is not an
// error: it comes back empty and marked new.
func loadIndex(id *age.X25519Identity) (*vaultIndex, error) {
	ct, err := os.ReadFile(indexPath())
	if errors.Is(err, fs.ErrNotExist) {
		return &vaultIndex{Files: map[string]*fileMeta{}, isNew: true}, nil
	}
	if err != nil {
		return nil, err
	}
	plain, err := decrypt(ct, id)
	if err != nil {
		return nil, fmt.Errorf("%s does not decrypt with this identity", indexPath())
	}
	var ix vaultIndex
	if err := json.Unmarshal(plain, &ix); err != nil || ix.Files == nil {
		return nil, fmt.Errorf("%s cannot be read", indexPath())
	}
	if !hmac.Equal([]byte(ix.MAC), []byte(indexMAC(ix.Files, id))) {
		return nil, fmt.Errorf("%s is not authentic: it was not written with this identity", indexPath())
	}
	return &ix, nil
}

// mustLoadIndex is loadIndex for commands that write the vault, which
// refuse to go on with an index they cannot trust.
func mustLoadIndex(id *age.X25519Identity, failed string) *vaultIndex {
	ix, err := loadIndex(id)
	if err != nil {
		die("%v; %s. To go on without descriptions and checksums, move it out of %s", err, failed, vaultDir)
	}
	return ix
}

// record notes that viage wrote ciphertext to the vault file name.
func (ix *vaultIndex) record(name string, ciphertext []byte) {
	now := time.Now().Format(time.RFC3339)
	m := ix.Files[name]
	if m == nil {
		m = &fileMeta{Added: now}
		ix.Files[name] = m
	}
	m.SHA256 = checksum(ciphertext)
	m.Updated = now
}

// seal returns the index encrypted and authenticated for id.
func (ix *vaultIndex) seal(id *age.X25519Identity) []byte {
	ix.MAC = indexMAC(ix.Files, id)
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		die("cannot write the index: %v", err)
	}
	return sealTo(append(b, '\n'), id)
}

func (ix *vaultIndex) save(id *age.X25519Identity) {
	publishOver(stage(ix.seal(id), indexPath()), indexPath())
}

// adopt records, in a new index, every vault file that decrypts with
// the identity, trusting them as they are now. It runs once, when the
// index is first created.
func (ix *vaultIndex) adopt(id *age.X25519Identity) {
	if !ix.isNew {
		return
	}
	for _, name := range vaultEntries() {
		path := filepath.Join(vaultDir, name)
		if !isVaultName(name) || name == indexName || sameFile(path, identityPath) {
			continue
		}
		if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() || ageKind(path) != "x25519" {
			continue
		}
		ct, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if _, err := decrypt(ct, id); err == nil {
			ix.record(name, ct)
		}
	}
	ix.isNew = false
}

func isVaultName(name string) bool {
	return strings.HasSuffix(name, ".age") || strings.HasSuffix(name, ".age.bak")
}

// cmdDescribe sets or clears the description of a vault file.
func cmdDescribe(args []string) {
	if len(args) < 1 || len(args) > 2 {
		usageError()
	}
	path := resolve(args[0])
	name := inVault(path)
	if name == "" || !isVaultName(name) || name == indexName {
		die("%s is not a file in %s", path, vaultDir)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		die("%s not found (see %s list)", path, prog)
	}
	text := ""
	if len(args) == 2 {
		text = strings.TrimSpace(args[1])
	}
	checkWritable()
	requireIdentity()
	lockVault()
	id := unlock()
	ix := mustLoadIndex(id, "nothing changed")
	ix.adopt(id)
	m := ix.Files[name]
	if m == nil {
		ct, err := os.ReadFile(path)
		if err != nil {
			die("cannot read %s: %v", path, err)
		}
		if _, err := decrypt(ct, id); err != nil {
			die("%s does not decrypt with this identity; %s add brings it in", path, prog)
		}
		ix.record(name, ct)
		m = ix.Files[name]
	}
	m.Description = text
	ix.save(id)
	if text == "" {
		warn("cleared the description of %s", name)
	} else {
		warn("described %s", name)
	}
}
