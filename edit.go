package main

// viage init, cat and edit (the default command): creating a vault or
// its index, printing a file, and editing one through a plaintext copy
// in the private RAM-backed directory.

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"filippo.io/age"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func cmdInit() {
	if exists(identityPath) && !exists(indexPath()) {
		initIndex()
		return
	}
	for _, f := range []string{identityPath, vaultFile, indexPath()} {
		if exists(f) {
			die("%s exists", f)
		}
	}
	mktmp()
	for _, d := range []string{vaultDir, filepath.Dir(identityPath), filepath.Dir(vaultFile)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			die("cannot create %s: %v", d, err)
		}
	}
	lockVault()

	fmt.Fprintln(os.Stderr, "Choose the vault passphrase.")
	// Armored, so the identity can be pasted into a password manager note.
	id, idFile := newIdentity("identity not created")
	publishNew(stage(idFile, identityPath), identityPath)
	vault := sealTo(nil, id)
	publishNew(stage(vault, vaultFile), vaultFile)
	ix := &vaultIndex{Files: map[string]*fileMeta{}}
	if name := inVault(vaultFile); name != "" {
		ix.record(name, vault)
		ix.Files[name].Description = "default vault"
	}
	publishNew(stage(ix.seal(id), indexPath()), indexPath())

	fmt.Fprintf(os.Stderr, "created %s\ncreated %s\n", identityPath, vaultFile)
	fmt.Fprintf(os.Stderr, "Back up the passphrase. Without it and %s the vault is lost.\n",
		filepath.Base(identityPath))
}

// initIndex makes the index for a vault that has none: one made before
// there was an index, or one whose index was moved out because it could
// not be trusted. Every file that decrypts with the identity is taken as
// it is now, so this is a deliberate step, never a side effect.
func initIndex() {
	checkWritable()
	requireIdentity()
	lockVault()
	id := unlock()
	if exists(indexPath()) {
		die("%s exists", indexPath())
	}
	ix := &vaultIndex{Files: map[string]*fileMeta{}, isNew: true}
	names := ix.adopt(id)
	publishNew(stage(ix.seal(id), indexPath()), indexPath())
	for _, n := range names {
		warn("indexed %s as it is now", n)
	}
	warn("created %s. The files above are taken as they are now; check any\n"+
		"you are unsure of with %s cat. Files not listed are left out.", indexPath(), prog)
}

// Say where cat's output is going and what will keep a copy of it.
// Printed before the passphrase prompt, so there is time to ^C.
func catWarning() {
	if term.IsTerminal(1) {
		warn("warning: printing plaintext to the terminal. Scrollback, a\n" +
			"multiplexer log, or an agent reading this terminal can keep it.")
		return
	}
	var st unix.Stat_t
	if unix.Fstat(1, &st) != nil {
		warn("warning: plaintext goes wherever stdout leads; a file on disk\n" +
			"outlives this command, in backups and snapshots too.")
		return
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFCHR:
		// /dev/null, or a device the user chose.
	case unix.S_IFREG:
		target := "a file"
		if p, err := os.Readlink("/proc/self/fd/1"); err == nil {
			target = p
		}
		switch fdFSType(1) {
		case "tmpfs", "ramfs", "mfs":
			warn("warning: writing plaintext to %s (RAM-backed); remove it when done.", target)
		default:
			warn("warning: writing plaintext to %s on persistent storage. It\n"+
				"outlives this command, in backups and snapshots too.", target)
		}
	case unix.S_IFIFO, unix.S_IFSOCK:
		warn("warning: plaintext goes to a pipe, and the reader decides where it\n" +
			"ends up. To copy, use wl-copy --sensitive, not plain wl-copy.")
	default:
		warn("warning: plaintext goes wherever stdout leads; a file on disk\n" +
			"outlives this command, in backups and snapshots too.")
	}
}

func cmdCat() {
	checkWritable()
	requireIdentity()
	if fi, err := os.Stat(vaultFile); err != nil || !fi.Mode().IsRegular() {
		die("%s not found (see %s list)", vaultFile, prog)
	}
	catWarning()
	id := unlock()
	f, err := os.Open(vaultFile)
	if err != nil {
		die("cannot decrypt %s: %v", vaultFile, err)
	}
	defer f.Close()
	r, err := age.Decrypt(openAge(f), id)
	if err != nil {
		die("cannot decrypt %s", vaultFile)
	}
	if _, err := io.Copy(os.Stdout, r); err != nil {
		die("cannot decrypt %s: %v", vaultFile, err)
	}
}

func requireIdentity() {
	if fi, err := os.Stat(identityPath); err != nil || !fi.Mode().IsRegular() {
		die("%s not found (run %s init)", identityPath, prog)
	}
}

func cmdEdit() {
	words := strings.Fields(editorCmd)
	if len(words) == 0 {
		die("no editor")
	}
	checkWritable(words[0])
	requireIdentity()
	if fi, err := os.Stat(vaultFile); err != nil || !fi.Mode().IsRegular() {
		die("%s not found (see %s list)", vaultFile, prog)
	}
	name := inVault(vaultFile)
	if name == indexName {
		die("%s is kept by %s; change descriptions with %s describe", vaultFile, prog, prog)
	}
	// Saving makes a backup of the file edited, and a backup of a backup
	// is one more file to keep track of for no gain.
	if strings.HasSuffix(vaultFile, ".age.bak") {
		die("%s is a backup, which edit leaves as it is; %s cat shows it", vaultFile, prog)
	}
	mktmp()
	// For the whole session, editor included, as vipw does.
	lockVault()

	// Keep the ciphertext as it was, so a change by anything else is
	// detected before saving.
	orig, err := os.ReadFile(vaultFile)
	if err != nil {
		die("cannot read %s: %v", vaultFile, err)
	}
	id := unlock()
	before, err := decrypt(orig, id)
	if err != nil {
		die("cannot decrypt %s", vaultFile)
	}
	var ix *vaultIndex
	if name != "" {
		ix = mustLoadIndex(id, "nothing was opened")
	}
	if bytes.IndexByte(before, 0) >= 0 {
		die("%s holds binary data; use %s cat to get it out", vaultFile, prog)
	}
	plain := filepath.Join(tmpDir, filepath.Base(vaultFile)+".txt")
	if err := os.WriteFile(plain, before, 0o600); err != nil {
		die("cannot write %s: %v", plain, err)
	}

	setEditing(true)
	err = runEditor(words, plain)
	setEditing(false)
	if sig := editorStopped(); sig != nil {
		warn("stopped by a signal (%v); changes discarded", sig)
		exit(128 + int(sig.(syscall.Signal)))
	}
	if err != nil {
		die("editor exited with an error; changes discarded")
	}
	after, err := os.ReadFile(plain)
	if err != nil {
		die("cannot read %s: %v", plain, err)
	}
	if bytes.Equal(before, after) {
		warn("no changes")
		return
	}

	ct := sealTo(after, id)
	if now, err := os.ReadFile(vaultFile); err != nil || !bytes.Equal(now, orig) {
		saved := fmt.Sprintf("%s.new.%d", vaultFile, os.Getpid())
		publishOver(stage(ct, vaultFile), saved)
		die("%s changed during the edit; your version is in %s", vaultFile, saved)
	}
	publishOver(stage(orig, vaultFile+".bak"), vaultFile+".bak")
	publishOver(stage(ct, vaultFile), vaultFile)
	if ix != nil {
		ix.record(name+".bak", orig)
		ix.record(name, ct)
		ix.save(id)
	}
	warn("saved %s", shown(vaultFile))
}

// runEditor runs the editor on file with swap, undo, backup and history
// files turned off. Known editors are started without user config or
// plugins, so nothing (an LSP, an AI completion plugin) gets to read the
// buffer. TMPDIR points at the private directory for anything else the
// editor writes.
func runEditor(words []string, file string) error {
	off := "set noundofile nobackup nowritebackup"
	// Y copies the visual selection, minus trailing newlines, marked
	// sensitive so a clipboard history that honors the hint (Omarchy's
	// does) skips it. The default yank stays in the editor's registers.
	copyMap := "echo"
	if _, err := exec.LookPath("wl-copy"); err == nil {
		copyMap = `xnoremap Y y:call system("wl-copy --sensitive", trim(@", "\n", 2))<Bar>echo v:shell_error ? "wl-copy failed; nothing copied" : "copied (sensitive)"<CR>`
	}
	args := words[1:]
	switch filepath.Base(words[0]) {
	case "nvim", "vim", "vi":
		// vi may be nvi or busybox, which do not know these flags.
		if filepath.Base(words[0]) == "vi" && !isVim(words[0]) {
			warn("unknown vi; check it writes no swap, backup or recovery files")
			args = append(args, file)
		} else {
			args = append(args, "--clean", "-n", "-i", "NONE", "-c", off, "-c", copyMap, file)
		}
	default:
		warn("unknown editor %s; check it writes no swap or backup files", words[0])
		args = append(args, file)
	}
	cmd := exec.Command(words[0], args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "TMPDIR="+tmpDir)
	if err := cmd.Start(); err != nil {
		return err
	}
	setEditor(cmd.Process)
	defer setEditor(nil)
	return cmd.Wait()
}

func isVim(path string) bool {
	out, _ := exec.Command(path, "--version").Output()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "VIM") || strings.HasPrefix(line, "NVIM") {
			return true
		}
	}
	return false
}
