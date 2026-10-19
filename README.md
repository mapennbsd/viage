# viage

Edit an [age](https://age-encryption.org)-encrypted file in your editor,
the way `vipw` edits the password file.

```
$ viage
Enter passphrase:
  ... editor opens, you edit, you save and quit ...
viage: saved secrets.age
```

One passphrase prompt per edit. The plaintext exists only in a RAM-backed
directory for as long as the editor is open, so the copies on disk, on a
file server, in snapshots and in cloud backups are always ciphertext.
The exceptions are the ones you choose: `viage cat` prints the plaintext
wherever you send it, and anything you copy goes to the clipboard.

viage is a small Go program built on [age's own
library](https://pkg.go.dev/filippo.io/age), which does all the
cryptography. It is about 1,800 lines with no other dependencies beyond
the Go project's `x/term` and `x/sys`; read it before trusting it with
secrets. Version 0.5 and earlier were a POSIX shell script; the Go
version reads the same vault.

## Why: secrets and AI agents

The old model of a workstation was that everything running as you was you.
Your home directory was inside the safety zone, so a token in a notes file,
a `.env` file or an unlocked password manager was protected as well as
your login was.

Coding and assistant agents break that model. They run as your user, with
your shell and your files, and they read widely: `grep -r` across a
directory, indexing a notes folder, opening whatever looks relevant.
Anything they read goes into their context. From there it is sent to a
model provider, written to a session transcript on disk, and is one prompt
injection away from being sent somewhere else. Most exposures are
accidental: the agent was looking for something else and the token was in
the same file. Some will be deliberate, steered by text the agent read in
an email or a web page.

viage keeps secrets out of that path:

- **At rest, the vault is ciphertext.** An agent that greps your files sees
  nothing useful, and there is no unlocked session for it to borrow.
- **Unlocking takes a human.** viage reads the passphrase from the
  terminal only, never from an environment variable, file or pipe. Do not
  store the passphrase anywhere an agent can read it.
- **The key is never written to a file.** The decrypted identity, which
  opens every file in the vault and every old copy of it, stays in
  viage's memory. On Linux that memory cannot be read by other processes
  running as you. Swap can still page it out; see
  [Swap](#what-it-protects-against-and-what-it-does-not).
- **The plaintext window is short.** Only the file you edit is written
  out, to a private directory in RAM that is removed when the editor
  exits. `cat`, `add` and `rekey` write no plaintext at all.
- **The editor runs without plugins.** vim and neovim start with no user
  config, so an AI completion plugin or language server never sees the
  buffer.

What viage cannot do is defend against a hostile process running as you.
While the editor is open, the file being edited is readable by your user.
And an agent that can write to your home directory could replace the
`viage` binary, or change your shell startup files or `$EDITOR`, to
capture the passphrase or the plaintext next time. For that threat the boundary has to
be a different user or a sandbox:

- Run agents under another user, in a container, or in their own sandbox,
  so they cannot read your runtime directory or write your startup files.
- Install viage root-owned (`/usr/local/bin`, mode 755) so it cannot be
  modified without root. Before asking for the passphrase, viage warns if
  it or the editor is writable by you, or sits in a
  directory you can write to. A replaced viage would simply drop the
  warning, so treat it as a check on how things are installed, not as
  tamper detection.
- Type the passphrase rather than pasting it. On most desktops any process
  running as you can read the clipboard, and clipboard managers write
  their history to disk. The same goes for secrets you copy out of the
  vault: see [Copying a secret](#copying-a-secret).
- Never paste a secret into an agent session. It stays in the transcript.

## viage and sops

[sops](https://github.com/getsops/sops) also opens an encrypted file in
your editor and supports age. They are built for different jobs.

| | viage | sops |
|---|---|---|
| For | secrets a person reads | secrets a program reads |
| Content | any text, encrypted whole | YAML, JSON, ENV or INI values; keys stay readable |
| What an onlooker sees | file names only; descriptions are encrypted | the names of every secret |
| Unattended decryption | no, by design | yes: `sops -d`, `sops exec-env`, cloud KMS |
| Plaintext during an edit | refused unless on tmpfs or ramfs | the system temp directory, which may be on disk |
| Editor | vim and neovim without config or plugins | `$EDITOR` with your full config |
| Keys | one age identity behind a passphrase | age, PGP, cloud KMS, HashiCorp Vault |
| Size | a small Go program on age's library | a large Go program |

Use sops for configuration that deployments and CI need to decrypt, where
diffable files in git matter. Use viage for the master copy of secrets
that only a human should open. They work well together: the age key that
your sops files use can itself live in the viage vault.

## Install

Build it with Go 1.26 or later; viage does not need the age command
itself. `wl-copy` is optional (see [Copying a secret](#copying-a-secret)).

```
CGO_ENABLED=0 go build -trimpath -o viage .
sudo install -o root -g root -m 755 viage /usr/local/bin/
viage init
```

The build is reproducible: the same source and Go version give the same
binary, byte for byte, so a build on one machine can be checked against
another. `go mod verify` checks the dependencies against `go.sum`.

Install it owned by root, as above, not in a directory you own such as
`~/.local/bin` or `~/bin`. A copy you can write to can be replaced by
anything running as you, including an AI agent, with a version that keeps
the passphrase. viage warns before the passphrase prompt if it or the
editor is writable by you (see [Why](#why-secrets-and-ai-agents)). On BSD
and macOS, use `-g wheel`.

`viage init` creates three files:

- `identity.age`: a fresh age identity, encrypted with your passphrase.
  It is ASCII-armored text, so it can be pasted into a password manager
  note as a backup.
- `secrets.age`: an empty vault, encrypted to that identity.
- `index.age`: descriptions and checksums of the vault files (see
  [Descriptions and checksums](#descriptions-and-checksums)).

A vault made by the shell versions of viage has no `index.age`. Run
`viage init` once to make it: with an identity already there, init
creates only the index, taking every file that opens with the identity
as it is now, and lists them. Commands that write the vault refuse to
run until there is an index.

All are safe to keep on shared or backed-up storage. To recover the vault
you need the passphrase and a copy of `identity.age`; keep both somewhere
other than where the vault lives.

The vault directory defaults to `~/.local/share/viage`, created mode 700,
and every file viage writes is mode 600. A local directory under your
home is the better place for it: snapshots and backups of your home
still get the ciphertext, and nothing else that shares a file server can
see it.

An identity created by an early viage is binary. viage and age read either form;
to convert one to text without re-encrypting it:

```
{ echo '-----BEGIN AGE ENCRYPTED FILE-----'
  base64 -w64 identity.age
  echo '-----END AGE ENCRYPTED FILE-----'; } > identity.age.txt
```

### On FreeBSD and OpenBSD

Neither has a RAM-backed directory for viage by default (`/tmp` is on
disk), so viage refuses until there is one. Mount a small one for your
user at boot and point `VIAGE_TMPDIR` at it (below, `you` is your user
and 1000 your uid). On FreeBSD, as root:

```
install -d -o you -g you -m 700 /home/you/.viage-tmp
echo 'tmpfs /home/you/.viage-tmp tmpfs rw,size=64m,mode=700,uid=1000,gid=1000 0 0' >> /etc/fstab
mount /home/you/.viage-tmp
```

On OpenBSD, an mfs. Each new mfs takes the owner and mode of the
directory it is mounted on, so it comes up yours at every boot:

```
install -d -o you -g you -m 700 /home/you/.viage-tmp
echo 'swap /home/you/.viage-tmp mfs rw,nodev,nosuid,-s=64m 0 0' >> /etc/fstab
mount /home/you/.viage-tmp
```

Then, in your shell profile:

```
export VIAGE_TMPDIR=/home/you/.viage-tmp
export VIAGE_EDITOR=vim
```

`vi` there is nvi, which can leave plaintext recovery files (see
[What it protects against](#what-it-protects-against-and-what-it-does-not)).
Swap can hold the tmpfs or mfs pages: OpenBSD encrypts it by default; on
FreeBSD use an `.eli` swap device.

### On macOS

macOS cannot report that a volume is in RAM, so viage takes
`VIAGE_TMPDIR` on trust: point it at a RAM disk, made after each boot,
private, and kept out of Spotlight:

```
dev=$(hdiutil attach -nomount ram://131072)
diskutil erasevolume HFS+ viage-tmp $dev
chmod 700 /Volumes/viage-tmp
sudo mdutil -i off /Volumes/viage-tmp
export VIAGE_TMPDIR=/Volumes/viage-tmp
```

For the same reason, `viage add` and `viage cat` treat a file on the RAM
disk as if it were on disk, and warn. Swap is encrypted by default.

## Use

```
viage              # edit $VIAGE_FILE
viage notes        # edit $VIAGE_DIR/notes.age
viage cat          # print $VIAGE_FILE to stdout
viage cat notes
viage add file...  # encrypt files into the vault and remove the originals
viage add -m "LUKS header backup, root" root.luks-header
viage describe notes "meeting notes"
viage list         # what is in the vault, without the passphrase
viage list -v      # with descriptions, checking every file
viage rekey        # new identity and passphrase for everything in $VIAGE_DIR
```

A name without a slash is a file in `$VIAGE_DIR`, with `.age` added if
it is missing. A name with a slash (`./notes.age`, `/mnt/x.age`) is a path.

Quit the editor with an error (`:cq` in vim) to discard your changes.
If the content did not change, the file is not rewritten. A file that
holds binary data, such as a LUKS header, is not opened in the editor;
use `viage cat` to get it out. Neither is a backup (`*.age.bak`), which
`viage cat` shows.

Like `vipw`, viage writes the vault one command at a time. `edit`, `add`,
`describe`, `rekey` and `init` take a lock (`$VIAGE_DIR/.lock`) and hold it until they
finish; an edit holds it for as long as the editor is open. Another
writer started meanwhile stops with "the vault is in use". Reading
(`cat`, `list`) needs no lock. The shell versions use the same lock, so
the two can share a vault. If viage was killed and left the lock
behind, it says which process held it; remove the directory once no
viage is running.

### What belongs in the vault

Every file in `$VIAGE_DIR` should be encrypted to the vault identity, so
that one passphrase opens all of it and `rekey` covers all of it. Keep
files under other keys somewhere else, and keep vault files directly in
`$VIAGE_DIR`: not in subdirectories, not behind symlinks, not with other
hard links. Rekey refuses to run while any are there (see
[Changing the passphrase](#changing-the-passphrase)). For a separate compartment, with
its own passphrase, make a second vault: another directory with its own
`identity.age`, used with `VIAGE_DIR=... viage`.

### Adding files

`viage add` encrypts each file to the identity, writes it into
`$VIAGE_DIR` as `name.age`, reads it back to verify it, and then removes
the original (`-k` keeps it). Every file is checked before the first is
written, and an existing vault file is never overwritten. A symlink is
refused, because deleting the link would leave the plaintext it points
to; add the file itself.

A file that is already age-encrypted is decrypted first and re-encrypted
to the identity. If it has a passphrase of its own, viage asks for it. That
is how a file made with `age -p` comes under the vault; if it is already
in `$VIAGE_DIR`, it is re-encrypted in place. A file encrypted to another
key is refused. Each source is read once, into memory; if it changes
before viage would remove it, it is kept.

Removing the original is an ordinary delete. On a copy-on-write
filesystem (btrfs, ZFS) nothing better is possible, and snapshots and
backups that already copied the file keep it. viage says so when the
original was plaintext on persistent storage. The clean way is never to
let the plaintext reach the disk: create it in a RAM-backed directory and
add it from there.

```
cryptsetup luksHeaderBackup /dev/nvme0n1p2 --header-backup-file /run/user/1000/root.luks-header
viage add /run/user/1000/root.luks-header
```

### Listing the vault

`viage list` shows each file with its size and date, labels the identity,
the default vault (`$VIAGE_FILE`) and the previous versions that edit
keeps (`*.age.bak`), and flags anything that does not belong: a file
that is not encrypted at all, a file with a passphrase of its own, a
file or directory open to other users, a held lock, and leftovers from
an interrupted edit, add or rekey. It reads only the age headers and
asks for no passphrase. A header shows whether a file has its
own passphrase or is encrypted to a key, but not which key; only `cat`,
`list -v` or `rekey` can confirm a file opens with the identity.

### Descriptions and checksums

`index.age` holds, for each vault file, a description, the dates it was
added and last written, and the SHA-256 of its ciphertext. viage updates
it whenever it writes a vault file. It is encrypted to the identity like
the rest, so descriptions are as private as the secrets; `list` without
`-v` shows only file names and the labels viage can tell for itself.

`viage list -v` asks for the passphrase, shows each description, and
checks every file against its checksum. It flags:

- **CHANGED OUTSIDE VIAGE:** the file is not what viage last wrote. It
  may be an older copy put back, a file swapped for another one from the
  vault, or a viage interrupted between writing a file and the index.
  Check it with `viage cat`. `viage add` on the file records it as it is.
- **MISSING:** in the index, but not in the vault.
- **not in the index:** a file that opens with the identity but that
  viage did not write. Check it with `viage cat`; `viage add` on the
  file records it.

age encryption does not prove who wrote a file: anyone who knows your
public key can encrypt to it. So the index also carries an HMAC keyed
from the identity, and viage refuses an index that does not verify.
Commands that write the vault stop rather than go on with it, or
without one. To start over, move `index.age` out of the vault and run
`viage init`, which makes a new index from every file that opens with
the identity, as it is at that moment. Nothing else rebuilds the index,
so a missing one never quietly becomes a fresh start.

What the index checks is the vault against the index that is there. It
cannot notice the whole vault, index included, being replaced by an
older copy, and once `index.age` is removed and init has run, it has no
memory of what came before. Only your own backups can tell you that.

### Copying a secret

vim and neovim run without your config, so yank (`y`) stays in the
editor's own registers and the mouse makes a visual selection. To copy
to the desktop clipboard, select the text and press `Y`. viage maps it to
`wl-copy --sensitive`, which drops trailing newlines and asks clipboard
managers not to record the copy. Omarchy's clipboard history honors the
request; check that yours does.

Avoid copying any other way: `"+y`, or a terminal selection with Shift
and the mouse. Those copies are not marked sensitive, so a clipboard
manager can write them to its history file on disk, where they end up
in snapshots and backups. The same is true of a secret you copy from
elsewhere to paste into the vault. `Y` needs Wayland and a wl-copy that has
`--sensitive`; without wl-copy, nothing is mapped.

### Printing to stdout

`viage cat` decrypts straight to stdout, for `grep` or a one-off pipe:

```
viage cat | grep -i telegram
viage cat | sed -n 's/^nut=//p' | wl-copy --sensitive
```

It is the one command that puts plaintext outside viage's control, so it
says where the output is going before it asks for the passphrase, leaving
time to press ^C:

- **A terminal:** the text stays in the scrollback, a multiplexer's log,
  and anything that reads the terminal. Never run it inside an agent's
  session, for example with `!` in Claude Code; the output goes into the
  transcript and to the model provider.
- **A file:** a file on persistent storage outlives the command, in
  snapshots and backups too. A file on tmpfs is reported as RAM-backed,
  but it stays until you remove it.
- **A pipe:** the reader decides where it ends up. To copy, use
  `wl-copy --sensitive`, not plain `wl-copy`.

An agent cannot run `viage cat` by itself, because viage reads the
passphrase from the terminal.

### Changing the passphrase

`viage rekey` makes a new identity under a new passphrase and re-encrypts
to it every file in `$VIAGE_DIR` that opens with the identity, along with
the index. It goes by what is in a file, not by its name, so hidden
files, backups and a default vault with another suffix are covered. The old identity
is replaced, not re-wrapped, because changing only the passphrase would
not revoke the old one. Every copy of the old `identity.age` (snapshots,
backups, a file server) would still open with the old passphrase, and it
would still decrypt the current vault.

After a rekey, copies of the old identity open only copies of the vault
made before the rekey. Those still hold your secrets as they were. If the
old passphrase may be known, rotate the secrets themselves.

Each file is decrypted, re-encrypted and verified in memory, written
beside the original as `*.rekey`, flushed to disk and read back before
anything is renamed. A failure up to that point changes nothing: the `*.rekey` files
are removed and the vault is as it was.

A file in `$VIAGE_DIR` that the identity does not open is skipped with a
warning and left as it is: one with its own passphrase (bring it in with
`viage add`), one encrypted to another key, or one that is not encrypted.
Skipping is safe, because a file the old identity cannot open is not
exposed by it either.

The old identity is deleted at the end, so rekey refuses to start, and
changes nothing, when anything could be left behind that only the old
identity opens:

- a file it cannot read, or a subdirectory it cannot search,
- a subdirectory holding an age file, or a symlink,
- a vault file with other hard links,
- a default vault (`$VIAGE_FILE`) that is not directly in `$VIAGE_DIR`,
- an unsaved edit (`*.new.*`) or a file left by an interrupted viage, or
- a previous rekey that did not finish.

It also checks every file against the index first, so that changing the
passphrase never accepts a file changed outside viage. A file that is
not in the index, or does not match it, stops the rekey; check it with
`viage cat`, and `viage add` on it records it as it is. A file in the
index that is gone from the vault is dropped from the index, with a
warning: a copy kept elsewhere opens only with the old identity.

Then the files are renamed into place, the identity first. Signals are
ignored during the renames, but a crash, a power loss or a failing disk
can still stop them partway. The old identity is kept as
`identity.age.old` until every file is in place and flushed to disk; if
the flush fails, it stays. An interrupted rename can be recovered by
hand, and the vault stays locked until it is:

- If `identity.age` is missing, rename `identity.age.rekey` to it.
- `identity.age` is then the new identity, and `identity.age.old` the old
  one.
- A file still named `X.age.rekey` is the new version of `X.age`; rename
  it over `X.age`.
- When no `*.rekey` file is left, remove `identity.age.old` and
  `$VIAGE_DIR/.lock`.

If the old passphrase still opens `identity.age`, the renames never
started: remove `identity.age.rekey`, every `*.rekey` and the lock, and
the vault is as it was.

Afterwards, update every copy of the passphrase and of `identity.age`
you keep elsewhere.

| Variable | Default |
|---|---|
| `VIAGE_DIR` | `$XDG_DATA_HOME/viage` |
| `VIAGE_IDENTITY` | `$VIAGE_DIR/identity.age` |
| `VIAGE_FILE` | `$VIAGE_DIR/secrets.age` |
| `VIAGE_TMPDIR` | the first RAM-backed of `$XDG_RUNTIME_DIR`, `/dev/shm`, `/tmp` |
| `VIAGE_EDITOR` | `$VISUAL`, `$EDITOR`, `vi` |

## How it works

1. Take the vault lock, and keep the ciphertext in memory to detect a
   change by anything else later.
2. Decrypt `identity.age` (the only prompt) in memory. The recipient is
   derived from it each time rather than read from a file, so a writable
   vault directory cannot redirect encryption to someone else's key.
3. Decrypt the vault into a file in a private directory on tmpfs and run
   the editor on it.
4. If the content changed: encrypt it, decrypt it again and compare, and
   check the vault was not changed meanwhile. Write the previous
   ciphertext to a new file beside the vault and rename it to
   `secrets.age.bak`, then do the same with the new ciphertext and
   `secrets.age`, and record both in the index. Each new file is created
   only if its name is new, mode 600, flushed to disk and read back; the
   rename replaces the old name rather than writing through it, so a
   symlink planted in the vault directory cannot redirect a write.
5. Remove the private directory and the lock, on any exit. If viage is
   sent HUP or TERM while the editor is open, it passes the signal on,
   kills the editor if it has not exited five seconds later, and waits
   for it before tidying up.

## What it protects against, and what it does not

viage protects the vault at rest: from agents and other programs reading
your files, a stolen disk, a compromised file server or backup host, a
cloud provider, an old snapshot. The passphrase is stretched with scrypt by
age, so its strength is what matters.

It does not protect against an attacker running as root, or running as
you while you edit: the file being edited sits in tmpfs, readable by your
user, for as long as the editor is open, and the editor's memory is as
readable as any of your processes. The decrypted identity is not in
tmpfs, and on Linux viage marks itself non-dumpable, so other processes
running as you cannot read its memory or its `/proc` files.

Points to be aware of:

- **Swap.** The file being edited in tmpfs, and viage's own memory with
  the identity and plaintext in it, can both be paged out to swap. Use
  encrypted swap, or zram only. OpenBSD encrypts swap by default; on
  FreeBSD use an `.eli` swap device.
- **Core dumps.** viage sets the core size limit to 0, and the editor
  inherits it, so a crash does not write their memory, plaintext
  included, to a core file. systemd-coredump honors the limit: it logs
  the crash and stores no core. If the limit, or on Linux the
  non-dumpable flag, cannot be set, viage stops before it asks for the
  passphrase.
- **The editor.** vim and neovim are started with `--clean -n -i NONE` and
  undo, backup and write-backup files turned off: no swap file, no history
  file, and no user config or plugins. Other editors are run as they are,
  with `TMPDIR` pointed at the private directory and a warning; check what
  they write and what plugins they load. The editor must not return before
  you are done (`code --wait`, not `code`).
- **Your terminal and clipboard.** Anything you copy out of the editor is
  outside viage's control. `Y` asks clipboard managers not to record it,
  and `viage cat` warns where its output is going. Terminal scrollback
  and clipboard managers that ignore the hint are up to you.
- **Rollback.** Someone who can write to the vault directory can replace
  a file with an older copy. age authenticates the content, so they
  cannot forge or alter it, and `list -v` flags a single file put back.
  Replacing the whole vault with an older copy, index included, goes
  unnoticed, and so does removing the index and running `viage init`.
- **Platforms.** viage asks the kernel whether the plaintext directory
  is RAM-backed: tmpfs or ramfs on Linux, tmpfs on FreeBSD, mfs on
  OpenBSD (a tmpfs or mfs `/tmp` is found by itself). If the type cannot
  be read, it refuses. On macOS a RAM disk looks like any other volume,
  so `VIAGE_TMPDIR` must be set and you vouch for it. Non-dumpable memory
  is Linux only; elsewhere viage sets the core limit alone. Tested on
  Arch Linux, Ubuntu 24.04, FreeBSD, OpenBSD 7.9 and macOS.
- **nvi.** `vi` on the BSDs is nvi, which viage runs as an unknown editor.
  Its working file goes to the private directory, but if it is killed or
  the terminal hangs up, it saves a recovery copy, in plaintext, to
  `/var/tmp/vi.recover`. Use `VIAGE_EDITOR=vim` or `nvim` there.
- **`viage cat` on BSD.** It can tell a file on disk from one in RAM,
  but not its name (there is no `/proc`), so the warning says "a file".

## Tests

```
go test ./...
CGO_ENABLED=0 go build -trimpath -o build/viage .
python3 tests/run.py
```

The Go tests cover what the binary cannot be driven into from outside.
`tests/run.py` is the test of record: it drives viage's passphrase
prompts through a pseudo-terminal and needs Python and the age command,
which it uses to make and check files independently of viage. It tests
`build/viage`, or the binary named by `VIAGE_BIN`. On the BSDs, set
`VIAGE_TMPDIR` first, as for normal use.

## License

ISC, the license OpenBSD uses; see [LICENSE](LICENSE). To report a
security problem, see [SECURITY.md](SECURITY.md).
