#!/usr/bin/env python3
"""End-to-end tests for viage.

age only reads passphrases from a terminal, so each run gets a pty and
the prompts are answered from here. The editor is a small shell script
chosen per test. Run from the repo root: python3 tests/run.py
"""

import os
import pty
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LINUX = sys.platform.startswith("linux")
# A RAM-backed directory for the tests' own scratch space.
RAMROOT = os.environ.get("VIAGE_TMPDIR") or os.environ.get("XDG_RUNTIME_DIR") or "/tmp"
# The program under test: build/viage, or the binary named by VIAGE_BIN.
VIAGE = os.path.abspath(os.environ.get("VIAGE_BIN") or os.path.join(ROOT, "build", "viage"))
PASS = "correct horse battery staple"
NEWPASS = "tr0ub4dor and 3"


def run(args, env, passphrase=PASS):
    """Run a command on a pty, answering passphrase prompts. Returns (status, output).

    passphrase may be a list, answered in order; the last one repeats.
    """
    answers = [passphrase] if isinstance(passphrase, str) else list(passphrase)
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe(args[0], args, env)
    out, pending = b"", b""
    while True:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data
        pending += data
        if b"passphrase" in pending.lower() and pending.rstrip().endswith(b":"):
            answer = answers.pop(0) if len(answers) > 1 else answers[0]
            os.write(fd, answer.encode() + b"\n")
            pending = b""
    os.close(fd)
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode(errors="replace")


def editor(env, body):
    path = os.path.join(env["HOME"], "editor.sh")
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, 0o755)
    env["VIAGE_EDITOR"] = path


def plaintext(env, passphrase=PASS, path=None):
    status, out = run(["age", "-d", "-o", env["HOME"] + "/id", env["VIAGE_IDENTITY"]], env, passphrase)
    assert status == 0, out
    try:
        return subprocess.run(
            ["age", "-d", "-i", env["HOME"] + "/id", path or env["VIAGE_FILE"]],
            check=True, capture_output=True, text=True,
        ).stdout
    finally:
        os.remove(env["HOME"] + "/id")


def ram_leftovers(env):
    d = env["VIAGE_TMPDIR"]
    return [n for n in os.listdir(d) if n.startswith("viage.")]


def vault_leftovers(env):
    """The lock and staged files must never outlive a command."""
    d = env["VIAGE_DIR"]
    if not os.path.isdir(d):
        return []
    return [n for n in os.listdir(d) if n == ".lock" or re.fullmatch(r"\..*\.age(\.bak)?\.\w{6}", n)]


def setup():
    home = tempfile.mkdtemp(prefix="viage-test.")
    ram = tempfile.mkdtemp(prefix="viage-test.", dir=RAMROOT)
    env = dict(os.environ, HOME=home, VIAGE_DIR=home + "/vault", VIAGE_TMPDIR=ram)
    env["VIAGE_IDENTITY"] = env["VIAGE_DIR"] + "/identity.age"
    env["VIAGE_FILE"] = env["VIAGE_DIR"] + "/secrets.age"
    status, out = run([VIAGE, "init"], env)
    if status != 0:
        teardown(env)
    assert status == 0, out
    return env


def teardown(env):
    shutil.rmtree(env["HOME"])
    shutil.rmtree(env["VIAGE_TMPDIR"])


def read(path):
    with open(path, "rb") as f:
        return f.read()


def test_init_and_edit(env):
    assert read(env["VIAGE_IDENTITY"]).startswith(b"-----BEGIN AGE ENCRYPTED FILE-----\n")
    assert plaintext(env) == ""
    editor(env, 'echo "token=abc123" >> "$1"')
    status, out = run([VIAGE], env)
    assert status == 0, out
    assert "saved" in out, out
    assert plaintext(env) == "token=abc123\n"
    assert os.path.exists(env["VIAGE_FILE"] + ".bak")


def test_init_refuses_existing(env):
    status, out = run([VIAGE, "init"], env)
    assert status != 0 and "exists" in out, out


def test_no_changes(env):
    before = read(env["VIAGE_FILE"])
    editor(env, ":")
    status, out = run([VIAGE], env)
    assert status == 0 and "no changes" in out, out
    assert read(env["VIAGE_FILE"]) == before


def test_editor_error_discards(env):
    before = read(env["VIAGE_FILE"])
    editor(env, 'echo junk >> "$1"; exit 1')
    status, out = run([VIAGE], env)
    assert status != 0 and "discarded" in out, out
    assert read(env["VIAGE_FILE"]) == before


def test_wrong_passphrase(env):
    before = read(env["VIAGE_FILE"])
    editor(env, 'echo junk >> "$1"')
    status, out = run([VIAGE], env, passphrase="wrong")
    assert status != 0, out
    assert read(env["VIAGE_FILE"]) == before


def test_concurrent_change(env):
    # Any different bytes will do: viage compares ciphertext, not content.
    other = env["HOME"] + "/other.age"
    shutil.copy(env["VIAGE_FILE"], other)
    with open(other, "ab") as f:
        f.write(b"x")
    editor(env, f'echo mine >> "$1"; cp {other} "$VIAGE_FILE"')
    status, out = run([VIAGE], env)
    assert status != 0 and "changed during the edit" in out, out
    assert read(env["VIAGE_FILE"]) == read(other)
    leftovers = [n for n in os.listdir(env["VIAGE_DIR"]) if ".new." in n]
    assert len(leftovers) == 1, leftovers


def test_plaintext_only_in_ram(env):
    editor(env, 'echo "$TMPDIR" > "$HOME/seen"; echo more >> "$1"')
    status, out = run([VIAGE], env)
    assert status == 0, out
    seen = open(env["HOME"] + "/seen").read().strip()
    assert seen.startswith(env["VIAGE_TMPDIR"] + "/viage."), seen
    assert not os.path.exists(seen)


def test_refuses_disk_tmpdir(env):
    # /tmp may itself be tmpfs, so use a directory beside the repo.
    disk = tempfile.mkdtemp(prefix=".viage-test.", dir=ROOT)
    try:
        env = dict(env, VIAGE_TMPDIR=disk)
        editor(env, ":")
        status, out = run([VIAGE], env)
        if sys.platform == "darwin":
            # A RAM disk looks like any other volume there, so an
            # explicit VIAGE_TMPDIR is taken on trust.
            assert status == 0, out
        else:
            assert status != 0 and "not tmpfs" in out, out
    finally:
        shutil.rmtree(disk)


def test_explicit_file(env):
    other = env["VIAGE_DIR"] + "/other.age"
    shutil.copy(env["VIAGE_FILE"], other)
    editor(env, 'echo other >> "$1"')
    status, out = run([VIAGE, other], env)
    assert status == 0, out
    assert plaintext(dict(env, VIAGE_FILE=other)).endswith("other\n")


def test_warns_writable(env):
    editor(env, ":")
    status, out = run([VIAGE], env)
    assert status == 0, out
    assert f"warning: {VIAGE} is writable" in out, out
    assert f"warning: {env['VIAGE_EDITOR']} is writable" in out, out


def test_no_warning_for_system_editor(env):
    env["VIAGE_EDITOR"] = "/usr/bin/true"
    status, out = run([VIAGE], env)
    assert status == 0, out
    assert "/usr/bin/true is writable" not in out, out
    assert "/usr/bin is writable" not in out, out


def add_secret(env, line="token=abc123"):
    editor(env, f'echo "{line}" >> "$1"')
    status, out = run([VIAGE], env)
    assert status == 0, out


def test_cat_terminal(env):
    add_secret(env)
    status, out = run([VIAGE, "cat"], env)
    assert status == 0, out
    assert "token=abc123" in out, out
    assert "printing plaintext to the terminal" in out, out
    # The warning comes before the prompt, so there is time to back out.
    assert out.index("warning: printing") < out.lower().index("passphrase"), out


def test_cat_to_pipe(env):
    add_secret(env)
    dest = env["HOME"] + "/out"
    status, out = run(["sh", "-c", f'"{VIAGE}" cat | cat > "{dest}"'], env)
    assert status == 0, out
    assert "goes to a pipe" in out and "wl-copy --sensitive" in out, out
    assert "token=abc123" not in out, out
    assert read(dest) == b"token=abc123\n"


def test_cat_to_disk_file(env):
    if not LINUX:
        return
    add_secret(env)
    disk = tempfile.mkdtemp(prefix=".viage-test.", dir=ROOT)
    try:
        dest = disk + "/out"
        status, out = run(["sh", "-c", f'"{VIAGE}" cat > "{dest}"'], env)
        assert status == 0, out
        assert f"writing plaintext to {dest} on persistent storage" in out, out
        assert read(dest) == b"token=abc123\n"
    finally:
        shutil.rmtree(disk)


def test_cat_to_ram_file(env):
    if not LINUX:
        return
    add_secret(env)
    dest = env["VIAGE_TMPDIR"] + "/out"
    status, out = run(["sh", "-c", f'"{VIAGE}" cat > "{dest}"'], env)
    assert status == 0, out
    assert "(RAM-backed)" in out, out
    os.remove(dest)


def test_cat_to_dev_null(env):
    status, out = run(["sh", "-c", f'"{VIAGE}" cat > /dev/null'], env)
    assert status == 0, out
    assert "plaintext" not in out, out


def test_cat_wrong_passphrase(env):
    add_secret(env)
    status, out = run([VIAGE, "cat"], env, passphrase="wrong")
    assert status != 0, out
    assert "token=abc123" not in out, out


def test_rekey(env):
    add_secret(env)
    add_secret(env, "second=xyz")  # leaves a .bak holding the first version
    other = env["VIAGE_DIR"] + "/other.age"
    shutil.copy(env["VIAGE_FILE"], other)
    status, out = run([VIAGE, "add", other], env)  # into the index
    assert status == 0, out
    old_identity = read(env["VIAGE_IDENTITY"])
    shutil.copy(env["VIAGE_IDENTITY"], env["HOME"] + "/old-identity.age")

    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0, out
    assert "rekeyed" in out and "rotate the secrets" in out, out
    assert read(env["VIAGE_IDENTITY"]) != old_identity
    assert read(env["VIAGE_IDENTITY"]).startswith(b"-----BEGIN AGE ENCRYPTED FILE-----\n")
    assert plaintext(env, NEWPASS) == "token=abc123\nsecond=xyz\n"
    assert plaintext(env, NEWPASS, other) == "token=abc123\nsecond=xyz\n"
    assert plaintext(env, NEWPASS, env["VIAGE_FILE"] + ".bak") == "token=abc123\n"
    status, out = run([VIAGE, "cat"], env, PASS)
    assert status != 0, out
    # The old identity no longer opens the vault.
    old = dict(env, VIAGE_IDENTITY=env["HOME"] + "/old-identity.age")
    status, out = run([VIAGE, "cat"], old, PASS)
    assert status != 0 and "cannot decrypt" in out, out
    leftovers = [n for n in os.listdir(env["VIAGE_DIR"]) if n.endswith((".rekey", ".old"))]
    assert not leftovers, leftovers


def vault_state(env):
    d = env["VIAGE_DIR"]
    return {n: read(os.path.join(d, n)) for n in sorted(os.listdir(d)) if os.path.isfile(os.path.join(d, n))}


def test_rekey_wrong_passphrase(env):
    add_secret(env)
    before = vault_state(env)
    status, out = run([VIAGE, "rekey"], env, ["wrong", NEWPASS])
    assert status != 0 and "cannot unlock" in out, out
    assert vault_state(env) == before


def foreign_key_file(env, path, content=b"other key\n"):
    subprocess.run(["age-keygen", "-o", env["HOME"] + "/foreign"], check=True, capture_output=True)
    subprocess.run(
        ["age", "-e", "-i", env["HOME"] + "/foreign", "-o", path],
        input=content, check=True,
    )


def own_passphrase_file(env, path, content="luks header\n", passphrase="their pass"):
    src = env["VIAGE_TMPDIR"] + "/src"
    with open(src, "w") as f:
        f.write(content)
    status, out = run(["age", "-p", "-o", path, src], env, passphrase)
    assert status == 0, out
    os.remove(src)


def test_rekey_skips_foreign_files(env):
    add_secret(env)
    foreign_key_file(env, env["VIAGE_DIR"] + "/zz.age")
    own_passphrase_file(env, env["VIAGE_DIR"] + "/hdr.age")
    with open(env["VIAGE_DIR"] + "/plain.age", "w") as f:
        f.write("not encrypted\n")
    untouched = {n: read(env["VIAGE_DIR"] + "/" + n) for n in ("zz.age", "hdr.age", "plain.age")}
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0, out
    assert "skipping" in out and "zz.age: it does not decrypt" in out, out
    assert "hdr.age: it has its own passphrase" in out, out
    assert "plain.age: it is not age-encrypted" in out, out
    # Only the vault passphrase and the new one were asked for.
    assert out.lower().count("passphrase:") + out.lower().count("passphrase for") <= 4, out
    assert plaintext(env, NEWPASS) == "token=abc123\n"
    for n, data in untouched.items():
        assert read(env["VIAGE_DIR"] + "/" + n) == data, n


def test_rekey_nothing_to_do(env):
    os.remove(env["VIAGE_FILE"])
    own_passphrase_file(env, env["VIAGE_DIR"] + "/hdr.age")
    before = vault_state(env)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS])
    assert status != 0 and "no vault files" in out, out
    assert vault_state(env) == before


def test_name_resolves_in_vault(env):
    shutil.copy(env["VIAGE_FILE"], env["VIAGE_DIR"] + "/other.age")
    editor(env, 'echo other >> "$1"')
    status, out = run([VIAGE, "other"], env)
    assert status == 0 and "saved " + env["VIAGE_DIR"] + "/other.age" in out, out
    status, out = run(["sh", "-c", f'"{VIAGE}" cat other.age > /dev/null'], env)
    assert status == 0, out
    status, out = run([VIAGE, "missing"], env)
    assert status != 0 and env["VIAGE_DIR"] + "/missing.age not found" in out, out


def mode(path):
    return os.stat(path).st_mode & 0o777


def test_add_from_ram(env):
    src = env["VIAGE_TMPDIR"] + "/api-token"
    with open(src, "w") as f:
        f.write("tok=1\n")
    status, out = run([VIAGE, "add", src], env)
    assert status == 0, out
    dest = env["VIAGE_DIR"] + "/api-token.age"
    assert "added " + dest + "; removed " + src in out, out
    assert "persistent storage" not in out, out
    assert not os.path.exists(src)
    assert plaintext(env, path=dest) == "tok=1\n"
    assert mode(dest) == 0o600


def test_add_from_disk_warns(env):
    disk = tempfile.mkdtemp(prefix=".viage-test.", dir=ROOT)
    try:
        src = disk + "/notes.txt"
        with open(src, "w") as f:
            f.write("note\n")
        status, out = run([VIAGE, "add", src], env)
        assert status == 0, out
        assert "was plaintext on persistent storage" in out, out
        assert not os.path.exists(src)
        assert plaintext(env, path=env["VIAGE_DIR"] + "/notes.txt.age") == "note\n"
    finally:
        shutil.rmtree(disk)


def test_add_keep(env):
    src = env["VIAGE_TMPDIR"] + "/k"
    with open(src, "w") as f:
        f.write("k\n")
    status, out = run([VIAGE, "add", "-k", src], env)
    assert status == 0 and "kept " + src in out, out
    assert os.path.exists(src)
    os.remove(src)


def test_add_refuses_existing(env):
    src = env["VIAGE_TMPDIR"] + "/secrets"
    with open(src, "w") as f:
        f.write("x\n")
    before = vault_state(env)
    status, out = run([VIAGE, "add", src], env)
    assert status != 0 and "secrets.age exists" in out, out
    assert "passphrase" not in out.lower(), out
    assert os.path.exists(src) and vault_state(env) == before
    os.remove(src)


def test_add_refuses_duplicate_names(env):
    a = env["VIAGE_TMPDIR"] + "/a"
    os.mkdir(a)
    for p in (a + "/n", env["VIAGE_TMPDIR"] + "/n"):
        with open(p, "w") as f:
            f.write("x\n")
    status, out = run([VIAGE, "add", a + "/n", env["VIAGE_TMPDIR"] + "/n"], env)
    assert status != 0 and "two files would be added" in out, out
    assert not os.path.exists(env["VIAGE_DIR"] + "/n.age")
    shutil.rmtree(a)
    os.remove(env["VIAGE_TMPDIR"] + "/n")


def test_add_own_passphrase_in_place(env):
    hdr = env["VIAGE_DIR"] + "/hdr.age"
    own_passphrase_file(env, hdr)
    os.chmod(hdr, 0o644)
    status, out = run([VIAGE, "add", hdr], env, [PASS, "their pass"])
    assert status == 0 and "re-encrypted " + hdr in out, out
    assert plaintext(env, path=hdr) == "luks header\n"
    assert mode(hdr) == 0o600
    # Now it is under the vault identity, rekey covers it.
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0 and "rekeyed " + hdr in out, out
    assert plaintext(env, NEWPASS, hdr) == "luks header\n"


def test_add_wrong_own_passphrase(env):
    hdr = env["VIAGE_DIR"] + "/hdr.age"
    own_passphrase_file(env, hdr)
    before = vault_state(env)
    status, out = run([VIAGE, "add", hdr], env, [PASS, "wrong"])
    assert status != 0 and "nothing added" in out, out
    assert vault_state(env) == before


def test_add_foreign_key_refused(env):
    src = env["VIAGE_TMPDIR"] + "/f.age"
    foreign_key_file(env, src)
    ok = env["VIAGE_TMPDIR"] + "/ok"
    with open(ok, "w") as f:
        f.write("fine\n")
    before = vault_state(env)
    # The good file comes first; nothing is written when a later one fails.
    status, out = run([VIAGE, "add", ok, src], env)
    assert status != 0 and "another key; nothing added" in out, out
    assert vault_state(env) == before
    assert os.path.exists(ok) and os.path.exists(src)
    os.remove(ok)
    os.remove(src)


def test_add_already_in_vault(env):
    before = vault_state(env)
    status, out = run([VIAGE, "add", env["VIAGE_FILE"]], env)
    assert status == 0 and "already in the vault" in out, out
    assert vault_state(env) == before


def test_binary_roundtrip_and_edit_refuses(env):
    data = bytes(range(256)) * 64
    src = env["VIAGE_TMPDIR"] + "/blob"
    with open(src, "wb") as f:
        f.write(data)
    status, out = run([VIAGE, "add", src], env)
    assert status == 0, out
    dest = env["VIAGE_DIR"] + "/blob.age"
    out_path = env["VIAGE_TMPDIR"] + "/blob.out"
    status, out = run(["sh", "-c", f'"{VIAGE}" cat blob > "{out_path}"'], env)
    assert status == 0, out
    assert read(out_path) == data
    os.remove(out_path)
    editor(env, 'echo x >> "$1"')
    before = read(dest)
    status, out = run([VIAGE, "blob"], env)
    assert status != 0 and "binary data" in out, out
    assert read(dest) == before


def test_list(env):
    add_secret(env)  # leaves secrets.age.bak
    shutil.copy(env["VIAGE_FILE"], env["VIAGE_DIR"] + "/other.age")
    own_passphrase_file(env, env["VIAGE_DIR"] + "/hdr.age")
    os.chmod(env["VIAGE_DIR"] + "/hdr.age", 0o644)
    with open(env["VIAGE_DIR"] + "/dropped.txt", "w") as f:
        f.write("oops\n")
    os.mkdir(env["VIAGE_DIR"] + "/subdir", 0o700)
    for n in ("a", "b"):
        open(env["VIAGE_DIR"] + "/subdir/" + n, "w").close()
    os.chmod(env["VIAGE_DIR"], 0o755)
    status, out = run([VIAGE, "list"], env)
    assert status == 0, out
    assert "wc:" not in out and "Is a directory" not in out, out
    assert "passphrase:" not in out.lower(), out
    lines = {l.split()[0]: l for l in out.splitlines() if l.strip() and not l.startswith("viage:")}
    assert "identity" in lines["identity.age"], out
    assert lines["secrets.age"].endswith("  default vault"), out
    assert lines["secrets.age.bak"].endswith("  previous version of secrets.age"), out
    assert lines["other.age"].endswith("  "), out
    assert "own passphrase" in lines["hdr.age"] and "open to others (-rw-r--r--" in lines["hdr.age"], out
    assert "NOT ENCRYPTED" in lines["dropped.txt"], out
    assert lines["subdir"].split()[1] == "-" and "not a regular file" in lines["subdir"], out
    # One line per entry, nothing from inside the subdirectory.
    entries = [l for l in out.splitlines() if l.strip() and not l.startswith("viage:")]
    assert len(entries) == len(os.listdir(env["VIAGE_DIR"])), out
    assert "is open to others" in out and "chmod 700" in out, out


def test_rekey_refuses_unsaved_edit(env):
    with open(env["VIAGE_FILE"] + ".new.123", "wb") as f:
        f.write(b"x")
    before = vault_state(env)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS])
    assert status != 0 and "unsaved edit" in out, out
    assert vault_state(env) == before


def test_rekey_refuses_unfinished_rekey(env):
    with open(env["VIAGE_FILE"] + ".rekey", "wb") as f:
        f.write(b"x")
    before = vault_state(env)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS])
    assert status != 0 and "did not finish" in out, out
    assert vault_state(env) == before


def test_rekey_abandoned_at_new_passphrase(env):
    # A confirmation that does not match makes age -p fail.
    before = vault_state(env)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, "different"])
    assert status != 0 and "nothing changed" in out, out
    assert vault_state(env) == before


# --- 0.5.0: rekey coverage, the vault lock, staging, symlinks, hardening


def test_rekey_covers_hidden_files(env):
    src = env["VIAGE_TMPDIR"] + "/.hidden"
    with open(src, "w") as f:
        f.write("hidden\n")
    status, out = run([VIAGE, "add", src], env)
    assert status == 0, out
    hidden = env["VIAGE_DIR"] + "/.hidden.age"
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0 and "rekeyed " + hidden in out, out
    assert plaintext(env, NEWPASS, hidden) == "hidden\n"


def test_rekey_refuses_subdirectory(env):
    sub = env["VIAGE_DIR"] + "/sub"
    os.mkdir(sub)
    shutil.copy(env["VIAGE_FILE"], sub + "/nested.age")
    before = vault_state_deep(env)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status != 0 and "nested.age is in a subdirectory" in out, out
    assert "passphrase" not in out.lower(), out
    assert vault_state_deep(env) == before


def test_rekey_refuses_default_vault_in_subdirectory(env):
    sub = env["VIAGE_DIR"] + "/sub"
    os.mkdir(sub)
    shutil.move(env["VIAGE_FILE"], sub + "/secrets.age")
    env = dict(env, VIAGE_FILE=sub + "/secrets.age")
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status != 0 and "in a subdirectory" in out, out


def test_rekey_refuses_symlinked_vault_file(env):
    elsewhere = env["HOME"] + "/elsewhere.age"
    shutil.copy(env["VIAGE_FILE"], elsewhere)
    os.symlink(elsewhere, env["VIAGE_DIR"] + "/linked.age")
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status != 0 and "linked.age is a symlink" in out, out


def vault_state_deep(env):
    state = {}
    for root, _, files in os.walk(env["VIAGE_DIR"]):
        for n in files:
            p = os.path.join(root, n)
            state[p] = read(p)
    return state


def hold_lock(env, pid):
    os.mkdir(env["VIAGE_DIR"] + "/.lock")
    with open(env["VIAGE_DIR"] + "/.lock/pid", "w") as f:
        f.write(f"{pid}\n")


def release_lock(env):
    shutil.rmtree(env["VIAGE_DIR"] + "/.lock")


def test_lock_refuses_writers(env):
    hold_lock(env, os.getpid())
    src = env["VIAGE_TMPDIR"] + "/x"
    with open(src, "w") as f:
        f.write("x\n")
    before = vault_state(env)
    editor(env, 'echo junk >> "$1"')
    for args in ([VIAGE], [VIAGE, "add", src], [VIAGE, "rekey"]):
        status, out = run(args, env)
        assert status != 0 and f"in use by process {os.getpid()}" in out, (args, out)
        assert "passphrase" not in out.lower(), out
    assert vault_state(env) == before and os.path.exists(src)
    # Readers do not need the lock.
    status, out = run(["sh", "-c", f'"{VIAGE}" cat > /dev/null'], env)
    assert status == 0, out
    status, out = run([VIAGE, "list"], env)
    assert status == 0 and f"lock held by process {os.getpid()}" in out, out
    release_lock(env)
    os.remove(src)


def test_stale_lock_is_reported(env):
    p = subprocess.Popen(["true"])
    p.wait()
    hold_lock(env, p.pid)
    status, out = run([VIAGE, "rekey"], env)
    assert status != 0 and f"left by process {p.pid}, which is not running" in out, out
    release_lock(env)


def test_edit_holds_lock_against_rekey_and_add(env):
    # The editor stands in for the user: while it is open, other writers
    # are turned away, and the edit still saves.
    src = env["VIAGE_TMPDIR"] + "/x"
    with open(src, "w") as f:
        f.write("x\n")
    log = env["HOME"] + "/inner.log"
    editor(env, f'''"{VIAGE}" rekey > "{log}" 2>&1 < /dev/null
"{VIAGE}" add "{src}" >> "{log}" 2>&1 < /dev/null
"{VIAGE}" >> "{log}" 2>&1 < /dev/null
echo mine >> "$1"''')
    status, out = run([VIAGE], env)
    assert status == 0 and "saved" in out, out
    inner = open(log).read()
    assert inner.count("the vault is in use") == 3, inner
    assert plaintext(env) == "mine\n"
    assert os.path.exists(src) and not os.path.exists(env["VIAGE_DIR"] + "/x.age")
    os.remove(src)


def test_backup_symlink_is_replaced_not_followed(env):
    add_secret(env)
    victim = env["HOME"] + "/victim"
    with open(victim, "w") as f:
        f.write("do not touch\n")
    bak = env["VIAGE_FILE"] + ".bak"
    os.remove(bak)
    os.symlink(victim, bak)
    add_secret(env, "second=1")
    assert open(victim).read() == "do not touch\n"
    assert not os.path.islink(bak) and mode(bak) == 0o600
    assert plaintext(env, path=bak) == "token=abc123\n"


def test_edit_tightens_modes(env):
    os.chmod(env["VIAGE_FILE"], 0o644)
    add_secret(env)
    assert mode(env["VIAGE_FILE"]) == 0o600
    assert mode(env["VIAGE_FILE"] + ".bak") == 0o600


def test_add_refuses_symlink_input(env):
    target = env["VIAGE_TMPDIR"] + "/real"
    with open(target, "w") as f:
        f.write("plain\n")
    link = env["VIAGE_TMPDIR"] + "/link"
    os.symlink(target, link)
    before = vault_state(env)
    status, out = run([VIAGE, "add", link], env)
    assert status != 0 and "is a symlink" in out, out
    assert vault_state(env) == before and os.path.exists(link)
    os.remove(link)
    os.remove(target)


def test_add_refuses_dangling_symlink_destination(env):
    os.symlink(env["HOME"] + "/nowhere", env["VIAGE_DIR"] + "/x.age")
    src = env["VIAGE_TMPDIR"] + "/x"
    with open(src, "w") as f:
        f.write("x\n")
    status, out = run([VIAGE, "add", src], env)
    assert status != 0 and "x.age exists" in out, out
    assert not os.path.exists(env["HOME"] + "/nowhere") and os.path.exists(src)
    os.remove(src)


def test_no_core_dumps(env):
    seen = env["HOME"] + "/core"
    editor(env, f'ulimit -c > "{seen}"')
    status, out = run([VIAGE], env)
    assert status == 0, out
    assert open(seen).read().strip() == "0"


# --- the index


def listing(env, *args, passphrase=PASS):
    status, out = run([VIAGE, "list", *args], env, passphrase)
    assert status == 0, out
    rows = {}
    for line in out.splitlines():
        if line.strip() and not line.startswith("viage:") and "passphrase" not in line.lower():
            rows[line.split()[0]] = line
    return out, rows


def test_index_created_by_init(env):
    assert os.path.exists(env["VIAGE_DIR"] + "/index.age")
    out, rows = listing(env)
    assert "passphrase" not in out.lower(), out
    assert "index (descriptions" in rows["index.age"], out
    out, rows = listing(env, "-v")
    assert rows["secrets.age"].endswith("  default vault"), out
    assert "CHANGED" not in out and "MISSING" not in out, out


def test_describe_and_add_m(env):
    src = env["VIAGE_TMPDIR"] + "/api-token"
    with open(src, "w") as f:
        f.write("tok\n")
    status, out = run([VIAGE, "add", "-m", "API token for the build bot", src], env)
    assert status == 0, out
    status, out = run([VIAGE, "describe", "secrets", "day-to-day secrets"], env)
    assert status == 0 and "described secrets.age" in out, out
    out, rows = listing(env)
    assert "API token" not in out and "day-to-day" not in out, out
    out, rows = listing(env, "-v")
    assert rows["api-token.age"].endswith("  API token for the build bot"), out
    assert rows["secrets.age"].endswith("  day-to-day secrets"), out
    status, out = run([VIAGE, "describe", "secrets"], env)
    assert status == 0 and "cleared" in out, out
    out, rows = listing(env, "-v")
    assert rows["secrets.age"].endswith("  default vault"), out


def test_list_v_detects_a_swapped_file(env):
    add_secret(env)
    add_secret(env, "second=1")
    # Both are genuine ciphertexts for this identity; only the index
    # can tell that secrets.age is not what viage last wrote.
    shutil.copy(env["VIAGE_FILE"] + ".bak", env["VIAGE_FILE"])
    out, rows = listing(env, "-v")
    assert "CHANGED OUTSIDE VIAGE" in rows["secrets.age"], out
    assert "CHANGED" not in rows["secrets.age.bak"], out


def test_forged_index_is_refused(env):
    # Encrypting to the identity needs only its public key, which anyone
    # who learns it can do. The index must still be rejected.
    status, out = run(["age", "-d", "-o", env["HOME"] + "/id", env["VIAGE_IDENTITY"]], env)
    assert status == 0, out
    recipient = subprocess.run(["age-keygen", "-y", env["HOME"] + "/id"],
                               capture_output=True, text=True, check=True).stdout.strip()
    os.remove(env["HOME"] + "/id")
    forged = b'{"files": {"secrets.age": {"sha256": "00"}}, "mac": "00"}\n'
    subprocess.run(["age", "-r", recipient, "-o", env["VIAGE_DIR"] + "/index.age"],
                   input=forged, check=True)
    out, rows = listing(env, "-v")
    assert "is not authentic" in out, out
    editor(env, 'echo x >> "$1"')
    before = vault_state(env)
    status, out = run([VIAGE], env)
    assert status != 0 and "not authentic" in out and "move it out" in out.lower(), out
    assert vault_state(env) == before


def test_list_v_reports_missing_files(env):
    src = env["VIAGE_TMPDIR"] + "/gone"
    with open(src, "w") as f:
        f.write("x\n")
    status, out = run([VIAGE, "add", src], env)
    assert status == 0, out
    os.remove(env["VIAGE_DIR"] + "/gone.age")
    out, rows = listing(env, "-v")
    assert "MISSING" in rows["gone.age"], out


def test_rekey_keeps_the_index(env):
    status, out = run([VIAGE, "describe", "secrets", "day-to-day secrets"], env)
    assert status == 0, out
    add_secret(env)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0, out
    out, rows = listing(env, "-v", passphrase=NEWPASS)
    assert rows["secrets.age"].endswith("  day-to-day secrets"), out
    assert "CHANGED" not in out and "not authentic" not in out, out


def test_index_is_not_edited_directly(env):
    editor(env, 'echo x >> "$1"')
    status, out = run([VIAGE, "index"], env)
    assert status != 0 and "describe" in out, out


def test_missing_index_needs_init(env):
    # A vault from before the index, or one whose index was removed:
    # nothing that writes rebuilds it on the side. init does, on purpose.
    add_secret(env)
    shutil.copy(env["VIAGE_FILE"], env["VIAGE_DIR"] + "/other.age")
    os.remove(env["VIAGE_DIR"] + "/index.age")
    out, rows = listing(env, "-v")
    assert "index.age is missing" in out, out
    before = vault_state(env)
    for args in (["describe", "other", "a copy"], ["rekey"]):
        status, out = run([VIAGE, *args], env, [PASS, NEWPASS, NEWPASS])
        assert status != 0 and "index.age is missing" in out and "init" in out, out
        assert vault_state(env) == before
    editor(env, 'echo x >> "$1"')
    status, out = run([VIAGE], env)
    assert status != 0 and "index.age is missing" in out, out
    assert vault_state(env) == before
    status, out = run([VIAGE, "init"], env)
    assert status == 0, out
    for n in ("secrets.age", "secrets.age.bak", "other.age"):
        assert f"indexed {n} as it is now" in out, out
    assert read(env["VIAGE_IDENTITY"]) == before["identity.age"]
    status, out = run([VIAGE, "describe", "other", "a copy"], env)
    assert status == 0, out
    out, rows = listing(env, "-v")
    assert "not in the index" not in out and "CHANGED" not in out, out
    assert rows["other.age"].endswith("  a copy"), out
    status, out = run([VIAGE, "init"], env)
    assert status != 0 and "exists" in out, out


# --- 1.0.0: what the review of the Go version found


def rekey_refused(env, needle, deep=False):
    before = (vault_state_deep if deep else vault_state)(env)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status != 0 and needle in out, out
    assert "Choose the new" not in out, out
    assert (vault_state_deep if deep else vault_state)(env) == before
    return out


def add_from_ram(env, name, content="x\n"):
    src = env["VIAGE_TMPDIR"] + "/" + name
    with open(src, "w") as f:
        f.write(content)
    status, out = run([VIAGE, "add", src], env)
    assert status == 0, out
    return env["VIAGE_DIR"] + "/" + name + ".age"


def test_rekey_covers_a_default_with_another_name(env):
    default = env["VIAGE_DIR"] + "/default.enc"
    shutil.copy(env["VIAGE_FILE"], default)
    env = dict(env, VIAGE_FILE=default)
    add_secret(env)  # saves default.enc and default.enc.bak
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0, out
    assert plaintext(env, NEWPASS) == "token=abc123\n"
    assert plaintext(env, NEWPASS, default + ".bak") == ""


def test_rekey_refuses_a_default_outside_the_vault(env):
    shutil.copy(env["VIAGE_FILE"], env["HOME"] + "/outside.age")
    # Starts with the vault directory, but is not in it.
    env = dict(env, VIAGE_FILE=env["VIAGE_DIR"] + "/../outside.age")
    rekey_refused(env, "the default vault, is not directly in")
    assert plaintext(env) == ""


def test_rekey_refuses_an_unreadable_file(env):
    if os.getuid() == 0:
        return
    locked = add_from_ram(env, "locked")
    os.chmod(locked, 0)
    try:
        before = os.listdir(env["VIAGE_DIR"])
        status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
        assert status != 0 and "cannot read " + locked in out, out
        assert "not age-encrypted" not in out, out
    finally:
        os.chmod(locked, 0o600)
    assert sorted(os.listdir(env["VIAGE_DIR"])) == sorted(before)
    assert plaintext(env, PASS, locked) == "x\n"


def test_rekey_refuses_an_unreadable_subdirectory(env):
    if os.getuid() == 0:
        return
    sub = env["VIAGE_DIR"] + "/sub"
    os.mkdir(sub)
    shutil.copy(env["VIAGE_FILE"], sub + "/nested.age")
    os.chmod(sub, 0)
    try:
        rekey_refused(env, "rekey must see every file")
    finally:
        os.chmod(sub, 0o700)


def test_rekey_finds_age_files_by_content(env):
    sub = env["VIAGE_DIR"] + "/sub"
    os.mkdir(sub)
    shutil.copy(env["VIAGE_FILE"], sub + "/notes.enc")
    rekey_refused(env, "notes.enc is in a subdirectory", deep=True)


def test_rekey_refuses_leftovers_and_hard_links(env):
    staged = env["VIAGE_DIR"] + "/.secrets.age.aB3dE9"
    shutil.copy(env["VIAGE_FILE"], staged)
    rekey_refused(env, "left by an interrupted viage")
    os.remove(staged)
    os.link(env["VIAGE_FILE"], env["HOME"] + "/elsewhere.age")
    rekey_refused(env, "other hard links")


def test_backups_are_not_edited(env):
    add_secret(env)
    editor(env, 'echo x >> "$1"')
    before = vault_state(env)
    status, out = run([VIAGE, "secrets.age.bak"], env)
    assert status != 0 and "is a backup" in out, out
    assert "passphrase" not in out.lower(), out
    assert vault_state(env) == before
    status, out = run([VIAGE, "cat", "secrets.age.bak"], env)
    assert status == 0, out


def test_rekey_refuses_a_file_changed_outside_viage(env):
    add_secret(env)
    add_secret(env, "second=1")
    shutil.copy(env["VIAGE_FILE"] + ".bak", env["VIAGE_FILE"])  # rolled back
    out = rekey_refused(env, "secrets.age changed outside viage")
    assert "viage add " + env["VIAGE_FILE"] in out, out
    status, out = run([VIAGE, "add", env["VIAGE_FILE"]], env)
    assert status == 0 and "recorded it in the index" in out, out
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0, out
    assert plaintext(env, NEWPASS) == "token=abc123\n"


def test_rekey_refuses_a_file_not_in_the_index(env):
    # Anyone with the public key can make a file that decrypts.
    shutil.copy(env["VIAGE_FILE"], env["VIAGE_DIR"] + "/dropped.age")
    rekey_refused(env, "dropped.age is not in the index")
    status, out = run([VIAGE, "describe", "dropped", "x"], env)
    assert status != 0 and "not in the index" in out, out


def test_rekey_refuses_a_tracked_file_replaced_by_another_key(env):
    gone = add_from_ram(env, "token")
    foreign_key_file(env, gone)
    rekey_refused(env, "token.age changed outside viage")


def test_rekey_drops_missing_files_from_the_index(env):
    gone = add_from_ram(env, "gone")
    os.remove(gone)
    status, out = run([VIAGE, "rekey"], env, [PASS, NEWPASS, NEWPASS])
    assert status == 0 and "gone.age is in the index but not in" in out, out
    out, rows = listing(env, "-v", passphrase=NEWPASS)
    assert "MISSING" not in out, out


def test_add_refuses_a_hard_link_to_the_destination(env):
    src = env["HOME"] + "/doc.age"
    with open(src, "w") as f:
        f.write("plain\n")
    os.link(src, env["VIAGE_DIR"] + "/doc.age")
    status, out = run([VIAGE, "add", src], env)
    assert status != 0 and "exists" in out, out
    assert read(src) == b"plain\n"


def test_add_refuses_plaintext_with_other_hard_links(env):
    src = env["VIAGE_TMPDIR"] + "/token"
    with open(src, "w") as f:
        f.write("tok\n")
    os.link(src, env["VIAGE_TMPDIR"] + "/token.copy")
    status, out = run([VIAGE, "add", src], env)
    assert status != 0 and "other hard links" in out, out
    assert not os.path.exists(env["VIAGE_DIR"] + "/token.age")
    status, out = run([VIAGE, "add", "-k", src], env)
    assert status == 0, out


def test_term_to_viage_alone_stops_the_editor(env):
    # viage under a shell that outlives it, so no terminal hangup
    # reaches the editor: only viage itself can stop it.
    import select, signal, time
    home = env["HOME"]
    editor(env, f'echo $$ > {home}/editor.pid; exec sleep 30')
    script = f'{VIAGE} & echo $! > {home}/viage.pid; wait; sleep 1'
    pid, fd = pty.fork()
    if pid == 0:
        os.execvpe("sh", ["sh", "-c", script], env)
    out, pending, sent, deadline = b"", b"", False, time.time() + 20
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                data = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            out += data
            pending += data
            if b"passphrase" in pending.lower() and pending.rstrip().endswith(b":"):
                os.write(fd, PASS.encode() + b"\n")
                pending = b""
        if not sent and os.path.exists(home + "/editor.pid") and os.path.getsize(home + "/editor.pid"):
            time.sleep(0.2)
            os.kill(int(open(home + "/viage.pid").read()), signal.SIGTERM)
            sent = True
    os.close(fd)
    os.waitpid(pid, 0)
    out = out.decode(errors="replace")
    assert sent, out
    assert "stopped by a signal (terminated)" in out, out
    try:
        os.kill(int(open(home + "/editor.pid").read()), 0)
        alive = True
    except ProcessLookupError:
        alive = False
    assert not alive, "the editor outlived viage"


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failed = 0
    for test in TESTS:
        env = setup()
        try:
            test(env)
            assert not ram_leftovers(env), ram_leftovers(env)
            assert not vault_leftovers(env), vault_leftovers(env)
            print(f"ok   {test.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {test.__name__}\n{e!r}" if not isinstance(e, AssertionError) else f"FAIL {test.__name__}\n{e}")
        finally:
            teardown(env)
    print(f"{len(TESTS) - failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
