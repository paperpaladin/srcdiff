# srcdiff

Finds code in a published artifact that was never in the repository.

This is the xz-utils shape. The backdoor was not in the git tree -- it was in the
release tarball, in build machinery that nobody was diffing against the source.
The check is trivial to state and annoying to do well.

```
$ python3 srcdiff.py audit attrs
package : attrs 26.1.0
sdist   : attrs-26.1.0.tar.gz
repo    : github.com/python-attrs/attrs
tag     : 26.1.0

130 files in the sdist, 129 in the repo at 26.1.0

  data-differs: non-code content differs
      .git_archival.txt
     1  generated: only in the artifact, but known to be generated (suppressed, -v to list)

No suspicious findings. Divergence is all generated or expected.
```

Standard library only. No `requests`, no `packaging`, no `diffoscope`.

## The actual problem

Legitimate divergence is the **norm**, not the exception. An sdist contains
`PKG-INFO` and `*.egg-info/` that no repository has. A repository contains
`.github/`, `tests/`, and `tox.ini` that no sdist ships. `setuptools-scm`
generates `_version.py`. `git archive` substitutes `.git_archival.txt`. Autotools
generates `configure` and `Makefile.in`.

So the work is not diffing -- it is **suppressing that noise without suppressing
the one finding that matters**. A tool that flags everything is as useless as one
that flags nothing, which is why the tests check severity bucketing and not just
detection.

Findings are bucketed:

| bucket | meaning |
|---|---|
| **HIGH-VENDORED** | vendored build machinery that does not match the canonical upstream copy it claims to be -- **the actual xz signature** |
| **HIGH** | code in the artifact with no counterpart in the repo |
| **MEDIUM** | code in both, with different content |
| repo-only | in the repo, missing from the artifact, not a usual exclusion |
| data-differs / artifact-only-data | non-code divergence |
| eol-only | differs only in line endings |
| generated / repo-only-expected | known-benign, counted and suppressed |

Exit 0 if nothing suspicious, 1 if HIGH or MEDIUM, 2 on error.

## Tests

16 planted divergences, each checked for detection **and** correct bucket.

```
$ make test
ok   identical archives are clean
ok   extra .py in the artifact is HIGH
ok   extra .sh in the artifact is HIGH
ok   extra .m4 in the artifact is HIGH
ok   extra .so in the artifact is HIGH
ok   changed .py content is MEDIUM
ok   PKG-INFO only in the artifact is suppressed
...
ok   clean release does not flag build-to-host.m4
ok   tampered release DOES flag build-to-host.m4
ok   and the tampered copy is reported as same-version, different-content
ok   clean run suppresses the vendored version skew
ok   clean run has at most 2 HIGH-VENDORED entries
ok   the only new finding is the injected file
ok   and it is build-to-host.m4
ok   tampered release exits nonzero
ok   the known nls.m4 survivor is still reported, not suppressed

25 passed, 0 failed
```

A detector nobody has watched fail is not evidence, so every suppression rule has
a test proving it suppresses the benign case, and the code-shaped cases have
tests proving they survive it. `build-to-host.m4` and `build-to-host.sh` -- the
actual xz filenames -- are in there.

The offline `compare` mode exists so these tests need no network: it takes two
local archives and does the same comparison.

## The xz test, and what it proved wrong

Everything above is a toy project with four files and one planted divergence.
Pointing the tool at a **real** release tarball is the only thing that answers the
question that matters, and the first time I did, the answer was no.

Against the genuine `xz-5.4.5` release tarball and its genuine git tag, srcdiff
produced **sixteen HIGH findings, all false** -- and every one of them was an
`m4/*.m4` file present in the tarball and absent from git. Which is the exact
shape of the xz-utils backdoor. The real signal would have been one line in
seventeen. That is not a detector; it is noise with an extra row.

The cause is structural. `libtoolize` and `gettextize` vendor those macros in
**from the build host**, so the project's repository is simply the wrong oracle
for them. And a name-based allowlist cannot rescue it, because:

> `build-to-host.m4` is a **legitimate gettext macro.** It ships at
> `/usr/share/aclocal/build-to-host.m4` on any machine with gettext installed.
> The attacker did not invent a filename. They shipped a modified copy of a real
> one -- which is precisely why it survived review.

So vendored files get a **second oracle**: the canonical copy on the build host.
And the in-band version marker -- `serial` for m4 macros, `scriptversion` /
`timestamp` / `VERSION` for `build-aux` scripts -- separates the two cases:

- **marker differs** -> a different upstream release, expected to differ, suppressed
- **marker matches, bytes differ** -> the file claims to be a revision it is not
  byte-identical to. **That is the signature.** A file modified in place does not
  advertise itself as a new release.

Result on the real artifacts: **16 false positives down to 1**, and an injected
`build-to-host.m4` surfaces immediately:

```
HIGH-VENDORED: vendored build machinery that does NOT match its canonical
               upstream copy -- this is the exact xz-utils signature
    m4/build-to-host.m4  serial 5, same as host, but content differs
                         (9242B canonical vs 9582B shipped, 8307c1f05ec9 vs 20f2290242b2)
    m4/nls.m4            serial 6, same as host, but content differs
                         (1236B canonical vs 1234B shipped, 421f67f14db7 vs dcd5942eb789)

22 vendored-version-skew (suppressed)
```

### Why the sample is not the real one

The compromised `xz-5.6.1` tarball has been purged from the archives it would be
fetched from -- `snapshot.debian.org` carries only `5.6.1+really5.4.5-1`, Debian's
revert. That is correct hygiene on their part, and it means the actual artifact is
not obtainable.

So `t/mkxzfixtures.sh` reproduces the **technique** against a clean release: the
genuine `/usr/share/aclocal/build-to-host.m4`, serial left intact, one comment
appended. No malicious content of any kind. Detection keys on **provenance** and
never on recognising a payload -- which is the only reason the check generalises
past this one incident, and the honest limit of what the test proves.

### The one false positive I left in

`m4/nls.m4` differs from this host's copy because upstream reflowed its header
comment from one line to two **without bumping the serial**. It stays reported.

One false positive in a 687-file tarball, which a human dismisses in ten seconds,
is a better place to stop than a normalisation rule broad enough to absorb
arbitrary comment changes. That rule would also absorb an injected comment block.

Fixtures are real trimmed upstream artifacts, regenerable with
`t/mkxzfixtures.sh` -- a fixture nobody can rebuild is a magic number.

## The live run found a bug the tests could not

The first `audit` against a real package resolved the repository to
`github.com/sponsors/hynek` -- a funding link -- and parsed `sponsors` as the
owner. The fix prefers `project_urls` keys that actually claim to be source, and
rejects a list of `github.com` paths that are not repositories.

No planted-divergence test would ever have caught that, because it is in the
metadata-resolution step rather than the comparison. Worth remembering before
trusting a suite that only tests the interesting part.

## Status

Works, on PyPI sdists against GitHub tags. Tag spelling is guessed from a short
list (`v1.2.3`, `1.2.3`, `release-1.2.3`) and the one that worked is printed.

Not implemented: wheels (they contain compiled output, so they need a different
comparison entirely), npm or crates.io or distro tarballs, GitLab or Codeberg,
signature verification, and the bulk mode that walks the top N packages and
reports aggregate findings. That last one is the point of the project and it is
the next milestone.

## License

GPL-3.0-or-later.
