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
- **Unlocking takes a human.** age reads the passphrase from the terminal
  only, never from an environment variable, file or pipe. Do not store the
  passphrase anywhere an agent can read it.
- **The plaintext window is short.** It exists only while you edit, in a
  private directory in RAM that is removed when the editor exits.
- **The editor runs without plugins.** vim and neovim start with no user
  config, so an AI completion plugin or language server never sees the
  buffer.

What viage cannot do is defend against a hostile process running as you.
While the editor is open, the plaintext is readable by your user. And an
agent that can write to your home directory could replace the `viage`
script, or change your shell startup files or `$EDITOR`, to capture the
passphrase or the plaintext next time. For that threat the boundary has to
be a different user or a sandbox:

- Run agents under another user, in a container, or in their own sandbox,
  so they cannot read your runtime directory or write your startup files.
- Install viage root-owned (`/usr/local/bin`, mode 755) so it cannot be
  modified without root. Before asking for the passphrase, viage warns if
  it, age, age-keygen or the editor is writable by you, or sits in a
  directory you can write to. A replaced viage would simply drop the
  warning, so treat it as a check on how things are installed, not as
  tamper detection.
- Type the passphrase rather than pasting it. On most desktops any process
  running as you can read the clipboard. The same goes for secrets you
  copy out of the vault.
- Never paste a secret into an agent session. It stays in the transcript.

## viage and sops

[sops](https://github.com/getsops/sops) also opens an encrypted file in
your editor and supports age. They are built for different jobs.

| | viage | sops |
|---|---|---|
| For | secrets a person reads | secrets a program reads |
| Content | any text, encrypted whole | YAML, JSON, ENV or INI values; keys stay readable |
| What an onlooker sees | nothing, not even what kind of secrets exist | the names of every secret |
| Unattended decryption | no, by design | yes: `sops -d`, `sops exec-env`, cloud KMS |
| Plaintext during an edit | refused unless on tmpfs or ramfs | the system temp directory, which may be on disk |
| Editor | vim and neovim without config or plugins | `$EDITOR` with your full config |
| Keys | one age identity behind a passphrase | age, PGP, cloud KMS, HashiCorp Vault |
| Size | one shell script | a large Go program |

Use sops for configuration that deployments and CI need to decrypt, where
diffable files in git matter. Use viage for the master copy of secrets
that only a human should open. They work well together: the age key that
your sops files use can itself live in the viage vault.

## Install

Requires `age` and `age-keygen` (v1.1 or later) and a POSIX shell.

```
sudo install -o root -g root -m 755 viage /usr/local/bin/
viage init
```

Install it owned by root, as above, not in a directory you own such as
`~/.local/bin` or `~/bin`. A copy you can write to can be replaced by
anything running as you, including an AI agent, with a version that keeps
the passphrase. viage warns before the passphrase prompt if it, age or the
editor is writable by you (see [Why](#why-secrets-and-ai-agents)). On BSD
and macOS, use `-g wheel`.

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

viage protects the vault at rest: from agents and other programs reading
your files, a stolen disk, a compromised file server or backup host, a
cloud provider, an old snapshot. The passphrase is stretched with scrypt by
age, so its strength is what matters.

It does not protect against an attacker running as you or as root on the
machine while you edit. The plaintext and the decrypted identity sit in
tmpfs, readable by your user, for as long as the editor is open.

Points to be aware of:

- **Swap.** tmpfs pages can be swapped out. Use encrypted swap, or zram
  only.
- **The editor.** vim and neovim are started with `--clean -n -i NONE` and
  undo, backup and write-backup files turned off: no swap file, no history
  file, and no user config or plugins. Other editors are run as they are,
  with `TMPDIR` pointed at the private directory and a warning; check what
  they write and what plugins they load. The editor must not return before
  you are done (`code --wait`, not `code`).
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
