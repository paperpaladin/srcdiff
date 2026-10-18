# srcdiff: plan

## Contract

```
srcdiff compare ARTIFACT REPO      two local archives, no network
srcdiff audit PACKAGE [VERSION]    fetch sdist from PyPI and tag from GitHub
```

Exit 0 = nothing suspicious, 1 = HIGH or MEDIUM findings, 2 = error. The exit
code is the contract: this has to be usable from CI without parsing output.

## Hard invariant

No false negatives in the HIGH buckets, and the false-positive rate must stay
low enough that a real finding is visible. The second half is not decoration. At
16 false positives per clean release the tool was useless *despite* having no
false negatives. A code-bearing file present in the
artifact and absent from the repository must always be reported, and no
suppression rule may ever hide one. Suppression rules are allowed to produce
false *positives* in the lower buckets. They are not allowed to swallow a HIGH.

Every suppression rule therefore owes two tests: one proving it suppresses the
benign case, one proving a code-shaped file still survives it.

## Oracle

1. `t/test_srcdiff.py`: 16 planted divergences, checked for detection and
   correct severity. Includes `build-to-host.m4` and `build-to-host.sh`, the real
   xz filenames.
2. Real packages, audited live. This is the oracle that found the
   `github.com/sponsors/...` bug, which no planted test could reach.
3. Real upstream artifacts. `t/fixtures/` holds trimmed copies of the genuine
   xz-5.4.5 release tarball and git tag. This is the oracle that proved the HIGH
   bucket was worthless on autotools projects (16 false positives, all of them the
   same shape as the attack) and that drove the vendored second-oracle design. The
   compromised 5.6.1 tarball itself is unobtainable, purged from the archives,
   so the technique is reproduced against a clean release instead, a real
   limit on what the test proves.

## Non-goals

Wheels, which contain compiled output and need a different comparison. Malware
analysis, this reports *divergence*, it does not judge intent. Signature or
provenance verification. That is a different tool.

## Commit sequence

- [x] 00 archive reading for tar.gz/tar/zip, root-directory stripping, hashing
      files: srcdiff.py
      proves: two identical archives with different root names compare clean
- [x] 01 severity classification with the generated/expected suppression lists
- [x] 02 planted-divergence tests, checking bucket as well as detection
      files: t/test_srcdiff.py
      proves: 16 passed, including the real xz filenames
- [x] 03 PyPI metadata fetch, sdist download, GitHub tag download with
      multi-spelling fallback
- [x] 04 fix: prefer source-ish project_urls keys, reject non-repo github paths
- [x] 05 the xz test against real upstream artifacts, and the redesign it forced
      why: 16 HIGH false positives on a genuine clean release, every one an m4
           file absent from git, i.e. indistinguishable from the real attack.
           Vendored build machinery comes from the BUILD HOST, so the repo is the
           wrong oracle for it; and build-to-host.m4 is a real gettext macro, so a
           name allowlist cannot separate benign from hostile either.
      files: srcdiff.py t/test_srcdiff.py t/mkxzfixtures.sh t/fixtures/
      proves: 16 false positives -> 1; an injected build-to-host.m4 with its serial
              intact is reported as HIGH-VENDORED; the delta between the clean and
              tampered runs is exactly the injection and nothing else
      why: the first live run resolved a Funding link and parsed "sponsors" as
           the repository owner

### Milestone 1: make the HIGH bucket trustworthy

- [x] 06 a corpus of 20 known-clean packages, asserting zero HIGH across all of
      them: the false-positive rate, measured, not assumed
      files: t/test_srcdiff.py
      done: 20 installed Python distributions read where they live, no network
            and nothing vendored into the repo. 5942 file comparisons, 0 HIGH,
            0 HIGH-VENDORED, 0 MEDIUM. Lower severity: 2135 generated (all
            .pyc, suppressed) and 151 artifact-only-data, every one of them a
            file inside a .dist-info directory. Clean-ness is re-established on
            every run: 3787 corpus files re-hashed against the publisher's own
            RECORD manifest, 0 mismatches. 78 distributions were present, 55
            qualify and the largest 20 are taken; the 23 dropped are printed
            with a reason (13 ship compiled objects, 9 have fewer than 10
            files, 1 is an editable install).
      proves: the gate is not vacuous. is_code() forced True -- the
            flags-everything failure -- turns all 20 packages red with 151
            HIGH; is_code() forced False fails the two planted cases, which
            run on every invocation. Two mutations it does NOT catch are
            recorded in the harness and the README.
      limit: the repo side is the publisher's manifest, not a git tree, because
            no artifact-and-repository pair exists on this machine. The xz
            fixtures remain the only place a real artifact meets a real repo.
- [ ] 07 cache downloads on disk, so 05 and 06 do not re-fetch on every run
- [ ] 08 `--json` output, so findings are machine-readable for 09

### Milestone 2: the actual point

- [ ] 09 bulk mode: walk the top 1000 PyPI packages by download count, audit
      each, aggregate the findings
      why: this is the deliverable. One package audited proves the tool works;
           1000 audited produces a finding worth writing up.
- [ ] 10 a taxonomy of what turns up, with the benign causes named and new
      suppression rules added, each with its pair of tests per the invariant
- [ ] 11 report the false-positive rate honestly alongside any real findings.
      A HIGH count with no denominator is not a result.
- [ ] 12 responsible disclosure for anything genuinely undisclosed, before
      publishing anything

### Milestone 3

- [ ] 13 npm tarballs against their declared repositories
- [ ] 14 Debian/Arch source tarballs against upstream tags, which is where the
      xz attack actually landed
- [ ] 15 GitLab and Codeberg, not just GitHub
- [ ] 16 run it as a CI action against a single package, for maintainers who want
      the check on their own releases

## Open questions

- Tag resolution is a guess. Doing it properly means reading the commit the sdist claims
  (`.git_archival.txt`, `PKG-INFO`'s metadata, or a `_version.py`) and fetches
  *that commit* instead of guessing a tag name. Worth doing before 09, since a
  wrong tag produces garbage findings at scale.
- Vendored dependencies will be the dominant false positive in bulk mode and are
  not handled at all yet. A vendored library is legitimately in the artifact and
  legitimately absent from the repo, and it is also exactly where you would hide
  something. No good automatic answer, probably needs to become its own
  bucket, not being suppressed or flagged.
