// viage keeps secrets in age-encrypted files, edited vipw style.
//
// The vault is a directory of files encrypted to one age identity, and
// the identity is itself encrypted with a passphrase. Each command asks
// for the passphrase once and keeps the identity in its own memory. The
// only plaintext written anywhere is the file being edited, in a private
// RAM-backed directory, for as long as the editor is open.
//
// Copyright (c) 2026 Matthew A. Pennington <mapennbsd@gmail.com>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	prog    = "viage"
	version = "1.0.1"
)

var (
	vaultDir     string
	identityPath string
	vaultFile    string
	editorCmd    string
)

func usage() string {
	return fmt.Sprintf(`usage: %[1]s [name]            edit a vault file (default: $VIAGE_FILE)
       %[1]s cat [name]        print a vault file to stdout
       %[1]s add [-k] [-m text] file...
                               encrypt files into the vault, then remove them
       %[1]s describe name [text]
                               set or clear the description of a vault file
       %[1]s list [-v]         show what is in the vault; -v unlocks it to
                               show descriptions and check every file
       %[1]s init              create the identity and an empty vault, or
                               the index for a vault that has none
       %[1]s rekey             new identity and passphrase; re-encrypt the vault
       %[1]s -h | -V

A name without a slash is a file in $VIAGE_DIR, with .age added if missing.

  VIAGE_DIR       %[2]s
  VIAGE_IDENTITY  %[3]s
  VIAGE_FILE      %[4]s
  VIAGE_TMPDIR    RAM-backed directory for plaintext
  VIAGE_EDITOR    editor command (default: $VISUAL, $EDITOR, vi)

Exit the editor with an error (:cq in vi) to discard changes.
In vim or neovim on Wayland, Y in visual mode copies the selection with
wl-copy --sensitive, which clipboard managers are asked not to record.
`, prog, vaultDir, identityPath, vaultFile)
}

func getenv(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func configure() {
	vaultDir = os.Getenv("VIAGE_DIR")
	if vaultDir == "" {
		data := os.Getenv("XDG_DATA_HOME")
		if data == "" {
			data = filepath.Join(os.Getenv("HOME"), ".local", "share")
		}
		vaultDir = filepath.Join(data, prog)
	}
	identityPath = getenv("VIAGE_IDENTITY")
	if identityPath == "" {
		identityPath = filepath.Join(vaultDir, "identity.age")
	}
	vaultFile = getenv("VIAGE_FILE")
	if vaultFile == "" {
		vaultFile = filepath.Join(vaultDir, "secrets.age")
	}
	editorCmd = getenv("VIAGE_EDITOR", "VISUAL", "EDITOR")
	if editorCmd == "" {
		editorCmd = "vi"
	}
}

// resolve returns the vault file a name refers to. A name with a slash
// is a path; anything else is a file in the vault directory, with .age
// added if missing.
func resolve(name string) string {
	switch {
	case strings.Contains(name, "/"):
		return name
	case strings.HasSuffix(name, ".age"), strings.HasSuffix(name, ".age.bak"):
		return filepath.Join(vaultDir, name)
	default:
		return filepath.Join(vaultDir, name+".age")
	}
}

func usageError() {
	fmt.Fprint(os.Stderr, usage())
	exit(2)
}

func main() {
	// Private files, no core dumps, and on Linux no reading of this
	// process's memory by other processes running as the same user.
	syscall.Umask(0o077)
	if err := harden(); err != nil {
		die("%v", err)
	}
	handleSignals()
	configure()

	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "-h", "--help":
		fmt.Print(usage())
	case "-V", "--version":
		fmt.Printf("%s %s\n", prog, version)
	case "init":
		if len(args) != 1 {
			die("init takes no arguments")
		}
		cmdInit()
	case "cat":
		if len(args) > 2 {
			usageError()
		}
		if len(args) == 2 {
			vaultFile = resolve(args[1])
		}
		cmdCat()
	case "add":
		cmdAdd(args[1:])
	case "describe":
		cmdDescribe(args[1:])
	case "list", "ls":
		switch {
		case len(args) == 1:
			cmdList(false)
		case len(args) == 2 && args[1] == "-v":
			cmdList(true)
		default:
			die("list takes only -v")
		}
	case "rekey":
		if len(args) != 1 {
			die("rekey takes no arguments")
		}
		cmdRekey()
	default:
		if strings.HasPrefix(cmd, "-") || len(args) > 1 {
			usageError()
		}
		if len(args) == 1 {
			vaultFile = resolve(args[0])
		}
		cmdEdit()
	}
	exit(0)
}
