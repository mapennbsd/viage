package main

// Unit tests for what the end-to-end suite (tests/run.py) cannot reach.
// That suite drives the binary through a pseudo-terminal and is the
// test of record for behavior; run both.

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAgeKind(t *testing.T) {
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	scrypt, _ := age.NewScryptRecipient("pw")
	scrypt.SetWorkFactor(10)

	cases := map[string][]byte{
		"x25519":  encrypt([]byte("a"), id.Recipient(), false),
		"armored": encrypt([]byte("a"), id.Recipient(), true),
		"scrypt":  encrypt([]byte("a"), scrypt, true),
		"hybrid":  encrypt([]byte("a"), hybrid.Recipient(), false),
		"plain":   []byte("token=abc123\n"),
		"empty":   nil,
		"damaged": []byte("age-encryption.org/v1\n-> X25519 garbage\n"),
	}
	want := map[string]string{
		"x25519":  "x25519",
		"armored": "x25519",
		"scrypt":  "scrypt",
		"plain":   "none",
		"empty":   "none",
		"damaged": "damaged",
	}
	for name, data := range cases {
		p := filepath.Join(dir, name)
		writeFile(t, p, data)
		got := ageKind(p)
		if name == "hybrid" {
			// Another kind of key: neither x25519 nor scrypt nor none.
			if got == "x25519" || got == "scrypt" || got == "none" || got == "damaged" {
				t.Errorf("hybrid: got %q", got)
			}
			continue
		}
		if got != want[name] {
			t.Errorf("%s: got %q, want %q", name, got, want[name])
		}
	}
}

func TestPickRAMDir(t *testing.T) {
	disk, ram := t.TempDir(), t.TempDir()
	typeOf := func(p string) string {
		switch p {
		case ram:
			return "tmpfs"
		case disk:
			return "btrfs"
		}
		return ""
	}
	unreadable := func(string) string { return "" }

	if d, err := pickRAMDir(ram, "", "linux", typeOf); err != nil || d != ram {
		t.Errorf("RAM VIAGE_TMPDIR: %q %v", d, err)
	}
	if _, err := pickRAMDir(disk, ram, "linux", typeOf); err == nil {
		t.Error("a disk VIAGE_TMPDIR was accepted")
	}
	// Failing closed: a type that cannot be read is refused, except
	// on macOS, where the user vouches for VIAGE_TMPDIR.
	if _, err := pickRAMDir(ram, "", "openbsd", unreadable); err == nil {
		t.Error("an unreadable filesystem type was accepted")
	}
	if d, err := pickRAMDir(disk, "", "darwin", typeOf); err != nil || d != disk {
		t.Errorf("macOS VIAGE_TMPDIR not trusted: %q %v", d, err)
	}
	if d, err := pickRAMDir("", ram, "linux", typeOf); err != nil || d != ram {
		t.Errorf("XDG_RUNTIME_DIR: %q %v", d, err)
	}
}

func TestStageAndPublish(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "x.age")

	s := stage([]byte("one"), dest)
	if fi, _ := os.Stat(s); fi.Mode().Perm() != 0o600 {
		t.Errorf("staged mode %v", fi.Mode().Perm())
	}
	if !stagedName.MatchString(filepath.Base(s)) {
		t.Errorf("list would not recognize a leftover %q", filepath.Base(s))
	}
	if err := linkNew(s, dest); err != nil {
		t.Fatal(err)
	}
	if exists(s) {
		t.Error("staged file left behind")
	}

	// linkNew never replaces: not a file, not a dangling symlink.
	s = stage([]byte("two"), dest)
	if err := linkNew(s, dest); !errors.Is(err, fs.ErrExist) {
		t.Errorf("replaced an existing file: %v", err)
	}
	link := filepath.Join(dir, "y.age")
	os.Symlink(filepath.Join(dir, "nowhere"), link)
	if err := linkNew(s, link); !errors.Is(err, fs.ErrExist) {
		t.Errorf("replaced a dangling symlink: %v", err)
	}
	if exists(filepath.Join(dir, "nowhere")) {
		t.Error("wrote through a dangling symlink")
	}

	// publishOver replaces a symlink and leaves its target alone.
	victim := filepath.Join(dir, "victim")
	writeFile(t, victim, []byte("do not touch"))
	bak := filepath.Join(dir, "x.age.bak")
	os.Symlink(victim, bak)
	publishOver(stage([]byte("backup"), bak), bak)
	if b, _ := os.ReadFile(victim); string(b) != "do not touch" {
		t.Error("wrote through a symlink")
	}
	if fi, _ := os.Lstat(bak); fi.Mode()&fs.ModeSymlink != 0 {
		t.Error("symlink not replaced")
	}
	os.Remove(s)
}

func TestSealToRoundTrip(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	ct := sealTo([]byte("secret\n"), id)
	if bytes.Contains(ct, []byte("secret")) {
		t.Error("plaintext in ciphertext")
	}
	pt, err := decrypt(ct, id)
	if err != nil || string(pt) != "secret\n" {
		t.Errorf("round trip: %q %v", pt, err)
	}
	other, _ := age.GenerateX25519Identity()
	if _, err := decrypt(ct, other); err == nil {
		t.Error("another identity decrypted it")
	}
}

func TestResolve(t *testing.T) {
	vaultDir = "/v"
	for in, want := range map[string]string{
		"notes":           "/v/notes.age",
		"notes.age":       "/v/notes.age",
		"secrets.age.bak": "/v/secrets.age.bak",
		"./notes.age":     "./notes.age",
		"/x/y.age":        "/x/y.age",
	} {
		if got := resolve(in); got != want {
			t.Errorf("resolve(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"/run/user/1000/api-token": "/v/api-token.age",
		"/tmp/hdr.age":             "/v/hdr.age",
		"/run/user/1000/.hidden":   "/v/.hidden.age",
	} {
		if got := addDest(in); got != want {
			t.Errorf("addDest(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVaultEntriesOrder(t *testing.T) {
	vaultDir = t.TempDir()
	for _, n := range []string{"b.age", ".h.age", "a.age", ".lock"} {
		writeFile(t, filepath.Join(vaultDir, n), nil)
	}
	got := strings.Join(vaultEntries(), " ")
	if got != "a.age b.age .h.age .lock" {
		t.Errorf("order: %s", got)
	}
}

func TestLsDate(t *testing.T) {
	recent := time.Now().Add(-time.Hour)
	if got := lsDate(recent); !strings.Contains(got, ":") {
		t.Errorf("recent: %q", got)
	}
	if got := lsDate(time.Date(2020, 3, 4, 5, 6, 0, 0, time.Local)); got != "Mar 4 2020" {
		t.Errorf("old: %q", got)
	}
}
