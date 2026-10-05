# viage

Edit an [age](https://age-encryption.org)-encrypted file in your editor,
the way `vipw` edits the password file.

```
$ viage
Enter passphrase for identity file "/home/me/.local/share/viage/identity.age":
  ... editor opens, you edit, you save and quit ...
viage: saved /home/me/.local/share/viage/secrets.age
```

One passphrase prompt per edit. The plaintext exists only in a RAM-backed
directory for as long as the editor is open, so the copies on disk, on a
file server, in snapshots and in cloud backups are always ciphertext.

viage is a single POSIX shell script with age doing all the cryptography.
It is short enough to read in a few minutes, which you should do before
trusting it with secrets.

## Install

Requires `age` and `age-keygen` (v1.1 or later) and a POSIX shell.

```
install -m 755 viage ~/.local/bin/
viage init
```

`viage init` creates two files:

- `identity.age`: a fresh age identity, encrypted with your passphrase.
  It is ASCII-armored text, so it can be pasted into a password manager
  note as a backup.
- `secrets.age`: an empty vault, encrypted to that identity.

Both are safe to keep on shared or backed-up storage. To recover the vault
you need the passphrase and a copy of `identity.age`; keep both somewhere
other than where the vault lives.

An identity created by an earlier viage is binary. age reads either form;
to convert one to text without re-encrypting it:

```
{ echo '-----BEGIN AGE ENCRYPTED FILE-----'
  base64 -w64 identity.age
  echo '-----END AGE ENCRYPTED FILE-----'; } > identity.age.txt
```

## Use

```
viage              # edit $VIAGE_FILE
viage other.age    # edit another file encrypted to the same identity
```

Quit the editor with an error (`:cq` in vim) to discard your changes.
If the content did not change, the file is not rewritten.

| Variable | Default |
|---|---|
| `VIAGE_DIR` | `$XDG_DATA_HOME/viage` |
| `VIAGE_IDENTITY` | `$VIAGE_DIR/identity.age` |
| `VIAGE_FILE` | `$VIAGE_DIR/secrets.age` |
| `VIAGE_TMPDIR` | first tmpfs of `$XDG_RUNTIME_DIR`, `/dev/shm` |
| `VIAGE_EDITOR` | `$VISUAL`, `$EDITOR`, `vi` |

## How it works

1. Copy the ciphertext aside, to detect a concurrent save later.
2. Decrypt `identity.age` (the only prompt) into a private directory on
   tmpfs. The recipient is derived from it each time rather than read from
   a file, so a writable vault directory cannot redirect encryption to
   someone else's key.
3. Decrypt the vault next to it and run the editor.
4. If the content changed: encrypt to a new file beside the vault, decrypt
   it again and compare, check that nobody else saved in the meantime, keep
   the previous ciphertext as `secrets.age.bak`, then rename the new file
   into place.
5. Remove the private directory, on any exit.

## What it protects against, and what it does not

viage protects the vault at rest: a stolen disk, a compromised file server
or backup host, a cloud provider, an old snapshot. The passphrase is
stretched with scrypt by age, so its strength is what matters.

It does not protect against an attacker running as you or as root on the
machine while you edit. The plaintext and the decrypted identity sit in
tmpfs, readable by your user, for as long as the editor is open.

Points to be aware of:

- **Swap.** tmpfs pages can be swapped out. Use encrypted swap, or zram
  only.
- **The editor.** vim and neovim are started with `--clean -n -i NONE` and
  undo, backup and write-backup files turned off: no swap file, no history
  file, and no user config or plugins (an LSP or AI completion plugin would
  otherwise see the buffer). Other editors are run as they are, with
  `TMPDIR` pointed at the private directory and a warning; check what they
  write. The editor must not return before you are done (`code --wait`,
  not `code`).
- **Your terminal and clipboard.** Anything you copy out of the editor is
  outside viage's control: clipboard managers, terminal scrollback.
- **Rollback.** Someone who can write to the vault directory can replace
  `secrets.age` with an older copy. age authenticates the content, so they
  cannot forge or alter it.
- **Platforms.** Tested on Linux, where viage checks that the plaintext
  directory is tmpfs or ramfs. Elsewhere it insists on `VIAGE_TMPDIR`, and
  you are responsible for it being RAM-backed.

## Tests

```
python3 tests/run.py
```

The tests drive age's passphrase prompts through a pseudo-terminal, so they
need nothing beyond Python and age.
