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
| **HIGH** | code in the artifact with no counterpart in the repo -- the xz shape |
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
ok   extra .py in the artifact is HIGH
ok   extra .sh in the artifact is HIGH
ok   extra .m4 in the artifact is HIGH
ok   changed .py content is MEDIUM
ok   PKG-INFO only in the artifact is suppressed
ok   line-ending-only difference is not a finding
ok   tests/ only in the repo is expected
...
16 passed, 0 failed
```

A detector nobody has watched fail is not evidence, so every suppression rule has
a test proving it suppresses the benign case, and the code-shaped cases have
tests proving they survive it. `build-to-host.m4` and `build-to-host.sh` -- the
actual xz filenames -- are in there.

The offline `compare` mode exists so these tests need no network: it takes two
local archives and does the same comparison.

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
