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


def eq(label, got, want):
    """Plain assertion. check() below is the fixture runner, not this."""
    global passed, failed
    if got == want:
        passed += 1
        print(f"ok   {label}")
    else:
        failed += 1
        print(f"FAIL {label}\n       got  {got!r}\n       want {want!r}")


def truthy(label, cond):
    eq(label, bool(cond), True)


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

# ============================================================================
# The xz test: a REAL autotools project, from real upstream artifacts.
#
# Everything above is a toy project with four files and one planted divergence.
# This section is the only part that answers the question that matters: does the
# HIGH bucket survive contact with a real release tarball, where HUNDREDS of files
# legitimately differ from git?
#
# The first run said no. Pointed at the genuine xz-5.4.5 release tarball against
# its genuine git tag, srcdiff produced SIXTEEN HIGH findings, all false, and every
# one of them was an m4/*.m4 file present in the tarball and absent from git --
# which is the exact shape of the xz-utils backdoor. The signal would have been one
# line in seventeen. That is not a detector.
#
# The cause is structural: libtoolize and gettextize vendor those macros in from the
# BUILD HOST, so the project's repository is simply the wrong oracle for them. And a
# name-based allowlist cannot help, because build-to-host.m4 is itself a legitimate
# gettext macro -- it ships in /usr/share/aclocal on any machine with gettext
# installed. The attacker did not invent a filename. They shipped a modified copy of
# a real one.
#
# So vendored files are checked against the canonical copy on this host, and the
# version marker (serial / scriptversion / timestamp / VERSION) separates "a
# different upstream release, expected to differ" from "claims to be this exact
# release and is not". The second is the xz signature.
#
# Fixtures are the real m4/ and build-aux/ trees from the real artifacts, trimmed
# to stay committable. The tampered one is the genuine gettext build-to-host.m4
# with its serial intact and a comment appended -- the TECHNIQUE, not the payload.
# Detection keys on provenance and never on recognising malicious content, which is
# the whole reason this approach can work at all.

FIX = HERE / "fixtures"


def run_files(artifact, repo):
    proc = subprocess.run(
        [sys.executable, str(SRCDIFF), "compare", str(FIX / artifact), str(FIX / repo)],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


if (FIX / "xz-5.4.5-gittag-vendored.tar.gz").exists():
    GIT = "xz-5.4.5-gittag-vendored.tar.gz"

    rc_clean, clean = run_files("xz-5.4.5-release-vendored.tar.gz", GIT)
    rc_tamp, tamp = run_files("xz-5.4.5-tampered-vendored.tar.gz", GIT)

    def high_lines(out):
        """Paths listed under HIGH-VENDORED."""
        keep, found = False, []
        for line in out.splitlines():
            if "HIGH-VENDORED:" in line:
                keep = True
                continue
            if keep:
                if not line.strip():
                    break
                if line.startswith("  ") and ":" not in line.split()[0]:
                    found.append(line.strip().split()[0])
        return found

    clean_high = high_lines(clean)
    tamp_high = high_lines(tamp)

    # The point of the whole exercise: an unmodified release must not put
    # build-to-host.m4 in the HIGH bucket, and a tampered one must.
    eq("clean release does not flag build-to-host.m4",
          any("build-to-host" in p for p in clean_high), False)
    eq("tampered release DOES flag build-to-host.m4",
          any("build-to-host" in p for p in tamp_high), True)
    eq("and the tampered copy is reported as same-version, different-content",
          "serial 5, same as host, but content differs" in tamp, True)

    # The 22 genuinely-skewed vendored files must stay out of the way in BOTH runs.
    # If this regresses, the signal drowns again exactly as it did the first time.
    truthy("clean run suppresses the vendored version skew",
           "vendored-version-skew" in clean)
    eq("clean run has at most 2 HIGH-VENDORED entries", len(clean_high) <= 2, True)

    # The delta between the two runs must be precisely the injection -- not a
    # general increase in alarm.
    delta = set(tamp_high) - set(clean_high)
    eq("the only new finding is the injected file", len(delta), 1)
    truthy("and it is build-to-host.m4",
           delta and "build-to-host" in next(iter(delta)))

    # Exit status is the CI contract.
    eq("tampered release exits nonzero", rc_tamp, 1)

    # The known survivor is asserted rather than normalised away. nls.m4 differs
    # from this host's copy only because upstream reflowed its header comment
    # without bumping the serial. One false positive in a 687-file tarball, which a
    # human dismisses in ten seconds, is a better place to stop than a
    # normalisation rule broad enough to absorb arbitrary comment changes -- that
    # rule would also absorb an injected comment block.
    eq("the known nls.m4 survivor is still reported, not suppressed",
          any("nls.m4" in p for p in clean_high), True)
else:
    print("SKIP xz fixtures absent; run t/mkxzfixtures.sh to rebuild them")

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
