#!/usr/bin/env python3
"""End-to-end tests for viage.

age only reads passphrases from a terminal, so each run gets a pty and
the prompts are answered from here. The editor is a small shell script
chosen per test. Run from the repo root: python3 tests/run.py
"""

import os
import pty
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VIAGE = os.path.join(ROOT, "viage")
PASS = "correct horse battery staple"


def run(args, env, passphrase=PASS):
    """Run a command on a pty, answering passphrase prompts. Returns (status, output)."""
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
            os.write(fd, passphrase.encode() + b"\n")
            pending = b""
    _, status = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(status), out.decode(errors="replace")


def editor(env, body):
    path = os.path.join(env["HOME"], "editor.sh")
    with open(path, "w") as f:
        f.write("#!/bin/sh\n" + body + "\n")
    os.chmod(path, 0o755)
    env["VIAGE_EDITOR"] = path


def plaintext(env):
    status, out = run(["age", "-d", "-o", env["HOME"] + "/id", env["VIAGE_IDENTITY"]], env)
    assert status == 0, out
    return subprocess.run(
        ["age", "-d", "-i", env["HOME"] + "/id", env["VIAGE_FILE"]],
        check=True, capture_output=True, text=True,
    ).stdout


def ram_leftovers(env):
    d = env["VIAGE_TMPDIR"]
    return [n for n in os.listdir(d) if n.startswith("viage.")]


def setup():
    home = tempfile.mkdtemp(prefix="viage-test.")
    ram = tempfile.mkdtemp(prefix="viage-test.", dir=os.environ["XDG_RUNTIME_DIR"])
    env = dict(os.environ, HOME=home, VIAGE_DIR=home + "/vault", VIAGE_TMPDIR=ram)
    env["VIAGE_IDENTITY"] = env["VIAGE_DIR"] + "/identity.age"
    env["VIAGE_FILE"] = env["VIAGE_DIR"] + "/secrets.age"
    status, out = run([VIAGE, "init"], env)
    assert status == 0, out
    return env


def teardown(env):
    shutil.rmtree(env["HOME"])
    shutil.rmtree(env["VIAGE_TMPDIR"])


def read(path):
    with open(path, "rb") as f:
        return f.read()


def test_init_and_edit(env):
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


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failed = 0
    for test in TESTS:
        env = setup()
        try:
            test(env)
            assert not ram_leftovers(env), ram_leftovers(env)
            print(f"ok   {test.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {test.__name__}\n{e}")
        finally:
            teardown(env)
    print(f"{len(TESTS) - failed}/{len(TESTS)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
