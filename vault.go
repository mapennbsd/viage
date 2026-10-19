package main

// What the commands share: passphrases, the private RAM-backed
// directory, the vault lock, writing files safely, age encryption, the
// identity, and checks on the programs viage trusts.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// --- passphrases

// readPassphrase prompts on the terminal and reads a line without echo.
// It never reads from stdin, a file or the environment: unlocking takes
// a person at a terminal.
func readPassphrase(prompt string) string {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		die("cannot read a passphrase: no terminal")
	}
	defer tty.Close()
	fd := int(tty.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		die("cannot read a passphrase: %v", err)
	}
	mu.Lock()
	termFd, termState = fd, state
	mu.Unlock()
	fmt.Fprint(tty, prompt)
	p, err := term.ReadPassword(fd)
	fmt.Fprintln(tty)
	mu.Lock()
	termState = nil
	mu.Unlock()
	if err != nil {
		die("cannot read a passphrase: %v", err)
	}
	return string(p)
}

// newPassphrase asks for a new passphrase twice.
func newPassphrase(failed string) string {
	p := readPassphrase("Enter new vault passphrase: ")
	if p == "" {
		die("the passphrase cannot be empty; %s", failed)
	}
	if readPassphrase("Confirm new vault passphrase: ") != p {
		die("the passphrases do not match; %s", failed)
	}
	return p
}

// --- the private RAM-backed directory

func isRAM(path string) bool {
	switch fsType(path) {
	case "tmpfs", "ramfs", "mfs":
		return true
	}
	return false
}

// ramDir returns a RAM-backed directory to hold plaintext, or fails. On
// macOS a RAM disk is an ordinary hfs or apfs volume, so VIAGE_TMPDIR is
// taken on trust there. Anywhere else a type that is not RAM-backed, or
// that cannot be read, is refused.
func ramDir() string {
	d, err := pickRAMDir(os.Getenv("VIAGE_TMPDIR"), os.Getenv("XDG_RUNTIME_DIR"), runtime.GOOS, fsType)
	if err != nil {
		die("%v", err)
	}
	return d
}

func pickRAMDir(explicit, runtimeDir, goos string, typeOf func(string) string) (string, error) {
	for _, d := range []string{explicit, runtimeDir, "/dev/shm", "/tmp"} {
		if d == "" {
			continue
		}
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() || unix.Access(d, unix.W_OK) != nil {
			continue
		}
		switch typeOf(d) {
		case "tmpfs", "ramfs", "mfs":
			return d, nil
		}
		if d == explicit {
			if goos != "darwin" {
				return "", fmt.Errorf("%s is not tmpfs, ramfs or mfs", d)
			}
			return d, nil
		}
	}
	return "", errors.New("no RAM-backed directory found; set VIAGE_TMPDIR")
}

func mktmp() {
	d, err := os.MkdirTemp(ramDir(), prog+".")
	if err != nil {
		die("cannot create a private directory: %v", err)
	}
	mu.Lock()
	tmpDir = d
	mu.Unlock()
}

// --- the vault lock

// lockVault holds the vault lock until exit, as vipw locks the password
// file, so no two commands write the vault at once. mkdir either creates
// the lock or fails, in one step, on any filesystem including NFS, and
// the shell versions of viage use the same lock. Commands that only read
// (cat, list) do not take it.
func lockVault() {
	if fi, err := os.Stat(vaultDir); err != nil || !fi.IsDir() {
		die("%s not found (run %s init)", vaultDir, prog)
	}
	l := filepath.Join(vaultDir, ".lock")
	if err := os.Mkdir(l, 0o700); err != nil {
		pid := lockPID(l)
		if pid > 0 && unix.Kill(pid, 0) == unix.ESRCH {
			die("%s was left by process %d, which is not running here; if no viage is running, remove it", l, pid)
		}
		held := ""
		if pid > 0 {
			held = fmt.Sprintf(" by process %d", pid)
		}
		die("the vault is in use%s; if no viage is running, remove %s", held, l)
	}
	mu.Lock()
	lockDir = l
	mu.Unlock()
	os.WriteFile(filepath.Join(l, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
}

func lockPID(l string) int {
	b, err := os.ReadFile(filepath.Join(l, "pid"))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

// --- writing files safely

const suffixChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomSuffix() string {
	b := make([]byte, 6)
	rand.Read(b)
	for i := range b {
		b[i] = suffixChars[int(b[i])%len(suffixChars)]
	}
	return string(b)
}

// stage writes data to a new file beside dest, flushes it to disk, reads
// it back to compare, and returns its name for publishOver or publishNew.
// The file is created only if the name is new, mode 600, so nothing
// planted in the directory (a symlink, a file with loose permissions)
// can redirect or expose the write.
func stage(data []byte, dest string) string {
	dir, base := filepath.Dir(dest), filepath.Base(dest)
	for range 100 {
		name := filepath.Join(dir, "."+base+"."+randomSuffix())
		f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			die("cannot create a file beside %s: %v", dest, err)
		}
		setPartial(name, true)
		_, err = f.Write(data)
		if err == nil {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			die("writing %s failed: %v", name, err)
		}
		if back, err := os.ReadFile(name); err != nil || !bytes.Equal(back, data) {
			die("writing %s failed: it reads back differently", name)
		}
		return name
	}
	die("cannot create a file beside %s", dest)
	return ""
}

// publishOver renames a staged file over dest, replacing it (even a
// symlink) rather than writing through it.
func publishOver(staged, dest string) {
	if err := os.Rename(staged, dest); err != nil {
		die("cannot rename %s to %s: %v", staged, dest, err)
	}
	setPartial(staged, false)
	mustSyncDir(filepath.Dir(dest))
}

// publishNew gives a staged file the name dest, which must not exist.
// A rename would replace dest; a hard link refuses to.
func publishNew(staged, dest string) {
	if err := linkNew(staged, dest); err != nil {
		if errors.Is(err, fs.ErrExist) {
			die("%s appeared meanwhile; nothing replaced", dest)
		}
		die("cannot create %s: %v", dest, err)
	}
}

func linkNew(staged, dest string) error {
	if err := os.Link(staged, dest); err != nil {
		return err
	}
	os.Remove(staged)
	setPartial(staged, false)
	mustSyncDir(filepath.Dir(dest))
	return nil
}

// syncDir flushes a directory, so that a rename in it survives a crash.
// A filesystem that cannot flush a directory at all (EINVAL, ENOTSUP)
// is not an error: there is nothing more to be done there.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) {
		return err
	}
	return nil
}

func mustSyncDir(dir string) {
	if err := syncDir(dir); err != nil {
		die("cannot flush %s to disk: %v", dir, err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// --- age files

// openAge returns a reader for an age file, armored or not.
func openAge(r io.Reader) io.Reader {
	br := bufio.NewReader(r)
	if peek, _ := br.Peek(len(armor.Header)); string(peek) == armor.Header {
		return armor.NewReader(br)
	}
	return br
}

// ageKind tells what protects a file, from its age header, without
// decrypting: "scrypt" (a passphrase of its own), "x25519" (a key,
// perhaps the identity), another stanza type, "damaged" for an age file
// whose header cannot be parsed, "none" for a file that is not
// age-encrypted, or "unreadable" when the file cannot be read, which
// says nothing about what is in it.
func ageKind(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "unreadable"
	}
	defer f.Close()
	er := &errReader{r: f}
	br := bufio.NewReader(er)
	peek, _ := br.Peek(len(armor.Header))
	var r io.Reader = br
	switch {
	case er.err != nil:
		return "unreadable"
	case string(peek) == armor.Header:
		r = armor.NewReader(br)
	case !bytes.HasPrefix(peek, []byte("age-encryption.org/")):
		return "none"
	}
	hdr, err := age.ExtractHeader(r)
	switch {
	case er.err != nil:
		return "unreadable"
	case err != nil:
		return "damaged"
	}
	var types []string
	for _, line := range strings.Split(string(hdr), "\n") {
		if t, ok := strings.CutPrefix(line, "-> "); ok {
			types = append(types, strings.Fields(t + " ?")[0])
		}
	}
	switch {
	case slices.Contains(types, "scrypt"):
		return "scrypt"
	case slices.Contains(types, "X25519"):
		return "x25519"
	case len(types) > 0:
		return types[0]
	}
	return "unknown"
}

// errReader remembers a read error other than the end of the file.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && err != io.EOF && e.err == nil {
		e.err = err
	}
	return n, err
}

// notOurs is true when decryption failed because the file is encrypted
// to some other key, rather than because it is damaged.
func notOurs(err error) bool {
	var e *age.NoIdentityMatchError
	return errors.As(err, &e)
}

func decrypt(ciphertext []byte, id age.Identity) ([]byte, error) {
	r, err := age.Decrypt(openAge(bytes.NewReader(ciphertext)), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func encrypt(plain []byte, r age.Recipient, armored bool) []byte {
	var buf bytes.Buffer
	var out io.Writer = &buf
	var a io.WriteCloser
	if armored {
		a = armor.NewWriter(&buf)
		out = a
	}
	w, err := age.Encrypt(out, r)
	if err != nil {
		die("encryption failed: %v", err)
	}
	if _, err := w.Write(plain); err != nil {
		die("encryption failed: %v", err)
	}
	if err := w.Close(); err != nil {
		die("encryption failed: %v", err)
	}
	if a != nil {
		a.Close()
	}
	return buf.Bytes()
}

// sealTo encrypts to the identity and checks the result decrypts again.
func sealTo(plain []byte, id *age.X25519Identity) []byte {
	ct := encrypt(plain, id.Recipient(), false)
	if back, err := decrypt(ct, id); err != nil || !bytes.Equal(back, plain) {
		die("verification failed")
	}
	return ct
}

// --- the identity

// unlock asks for the passphrase and returns the identity. It is kept
// in memory only. The recipient is derived from it each time rather
// than read from a file, so a writable vault directory cannot redirect
// encryption to someone else's key.
func unlock() *age.X25519Identity {
	data, err := os.ReadFile(identityPath)
	if err != nil {
		die("cannot read %s: %v", identityPath, err)
	}
	// The path only when it is not the usual identity, so an unusual
	// one stands out.
	prompt := "Enter passphrase: "
	if identityPath != filepath.Join(vaultDir, "identity.age") {
		prompt = fmt.Sprintf("Enter passphrase for %s: ", identityPath)
	}
	p := readPassphrase(prompt)
	sid, err := age.NewScryptIdentity(p)
	if err != nil {
		die("cannot unlock identity")
	}
	plain, err := decrypt(data, sid)
	if err != nil {
		die("cannot unlock identity: %v", err)
	}
	ids, err := age.ParseIdentities(bytes.NewReader(plain))
	clear(plain)
	if err != nil || len(ids) != 1 {
		die("cannot unlock identity: it holds no single age identity")
	}
	x, ok := ids[0].(*age.X25519Identity)
	if !ok {
		die("cannot unlock identity: not an X25519 identity")
	}
	return x
}

// newIdentity makes an identity and returns it with its file contents,
// armored and encrypted with a new passphrase. The text inside is what
// age-keygen writes, so age and older viage read it.
func newIdentity(failed string) (*age.X25519Identity, []byte) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		die("cannot generate an identity: %v", err)
	}
	p := newPassphrase(failed)
	r, err := age.NewScryptRecipient(p)
	if err != nil {
		die("%v; %s", err, failed)
	}
	text := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n",
		time.Now().Format(time.RFC3339), id.Recipient(), id)
	return id, encrypt([]byte(text), r, true)
}

// --- programs viage trusts

// checkWritable warns about each program viage trusts with plaintext
// that a process running as you could replace: viage itself and the
// editor. Being writable by you is how an agent or other same-user
// process would swap in a version that keeps a copy. A replaced viage
// would simply drop this check, so it flags how things are installed;
// it does not detect tampering.
func checkWritable(cmds ...string) {
	if os.Getuid() == 0 {
		return
	}
	if self, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(self); err == nil {
			self = real
		}
		writable(self)
	}
	for _, c := range cmds {
		if p, err := exec.LookPath(c); err == nil && strings.Contains(p, "/") {
			writable(p)
		}
	}
}

func writable(p string) {
	if canWrite(p) {
		warn("warning: %s is writable by you; anything running as you could replace it", p)
	} else if canWrite(filepath.Dir(p)) {
		warn("warning: %s is writable by you; anything running as you could replace %s", filepath.Dir(p), p)
	}
}

// canWrite reports whether you could write p. On FreeBSD and OpenBSD,
// access says ETXTBSY for any program that is running, viage itself
// included, whoever may write it; then the owner and mode decide (ACLs
// are not read).
func canWrite(p string) bool {
	err := unix.Access(p, unix.W_OK)
	if err != unix.ETXTBSY {
		return err == nil
	}
	var st unix.Stat_t
	if unix.Stat(p, &st) != nil {
		return false
	}
	switch {
	case int(st.Uid) == os.Getuid():
		return st.Mode&0o200 != 0
	case inGroup(int(st.Gid)):
		return st.Mode&0o020 != 0
	}
	return st.Mode&0o002 != 0
}

func inGroup(gid int) bool {
	if gid == os.Getgid() {
		return true
	}
	gs, _ := os.Getgroups()
	return slices.Contains(gs, gid)
}

// looseMode returns the mode of a file if anyone but its owner has
// access to it, or "".
func looseMode(fi fs.FileInfo) string {
	if fi.Mode().Perm()&0o077 == 0 {
		return ""
	}
	return fi.Mode().String()
}
