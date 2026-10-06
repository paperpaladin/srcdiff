# srcdiff -- plan

## Contract

```
srcdiff compare ARTIFACT REPO      two local archives, no network
srcdiff audit PACKAGE [VERSION]    fetch sdist from PyPI and tag from GitHub
```

Exit 0 = nothing suspicious, 1 = HIGH or MEDIUM findings, 2 = error. The exit
code is the contract: this has to be usable from CI without parsing output.

## Hard invariant

**No false negatives in the HIGH bucket.** A code-bearing file present in the
artifact and absent from the repository must always be reported, and no
suppression rule may ever hide one. Suppression rules are allowed to produce
false *positives* in the lower buckets; they are not allowed to swallow a HIGH.

Every suppression rule therefore owes two tests: one proving it suppresses the
benign case, one proving a code-shaped file still survives it.

## Oracle

1. `t/test_srcdiff.py` -- 16 planted divergences, checked for detection **and**
   correct severity. Includes `build-to-host.m4` and `build-to-host.sh`, the real
   xz filenames.
2. Real packages, audited live. This is the oracle that found the
   `github.com/sponsors/...` bug, which no planted test could reach.
3. (Not yet) the historical xz-utils 5.6.0 and 5.6.1 tarballs against their git
   tags. The tool should light up. Until it does, the HIGH bucket is untested
   against a real attack.

## Non-goals

Wheels, which contain compiled output and need a different comparison. Malware
analysis -- this reports *divergence*, it does not judge intent. Signature or
provenance verification; that is a different tool.

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
      why: the first live run resolved a Funding link and parsed "sponsors" as
           the repository owner

### Milestone 1 -- make the HIGH bucket trustworthy

- [ ] 05 **the xz regression test**: fetch xz-utils 5.6.1's release tarball and
      its git tag, assert `build-to-host.m4` lands in HIGH
      why: the one test that proves this tool would have caught the real thing.
           Until it exists, the HIGH bucket is only tested against my own
           imagination of an attack.
- [ ] 06 a corpus of 20 known-clean packages, asserting zero HIGH across all of
      them -- the false-positive rate, measured rather than assumed
- [ ] 07 cache downloads on disk, so 05 and 06 do not re-fetch on every run
- [ ] 08 `--json` output, so findings are machine-readable for 09

### Milestone 2 -- the actual point

- [ ] 09 bulk mode: walk the top 1000 PyPI packages by download count, audit
      each, aggregate the findings
      why: this is the deliverable. One package audited proves the tool works;
           1000 audited produces a finding worth writing up.
- [ ] 10 a taxonomy of what turns up, with the benign causes named and new
      suppression rules added -- each with its pair of tests per the invariant
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

- Tag resolution is a guess. The robust version reads the commit the sdist claims
  (`.git_archival.txt`, `PKG-INFO`'s metadata, or a `_version.py`) and fetches
  *that commit* instead of guessing a tag name. Worth doing before 09, since a
  wrong tag produces garbage findings at scale.
- Vendored dependencies will be the dominant false positive in bulk mode and are
  not handled at all yet. A vendored library is legitimately in the artifact and
  legitimately absent from the repo, and it is also exactly where you would hide
  something. No good automatic answer -- probably needs to become its own bucket
  rather than being suppressed or flagged.
