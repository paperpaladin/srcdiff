#!/bin/sh
# Rebuild the xz fixtures in t/fixtures/ from upstream. Needs network.
#
# The committed fixtures are trimmed copies of real upstream artifacts, so they can
# be checked in without carrying a 3MB tarball. This script is how they were made
# and is the only reason to trust them: a fixture nobody can regenerate is a magic
# number.
#
# Three archives:
#   xz-5.4.5-gittag-vendored.tar.gz    the real git tag's m4/ + configure.ac
#   xz-5.4.5-release-vendored.tar.gz   the real release tarball's m4/ + build-aux/
#   xz-5.4.5-tampered-vendored.tar.gz  the same, plus an injected build-to-host.m4
#
# Why 5.4.5 and not 5.6.1: the compromised 5.6.1 tarball has been purged from the
# places it would be fetched from. snapshot.debian.org carries only
# "5.6.1+really5.4.5-1", Debian's revert. That is correct archive hygiene and it
# means the actual sample is not obtainable, so the attack's TECHNIQUE is
# reproduced against a clean release instead.
#
# What the injection is, precisely: the genuine /usr/share/aclocal/build-to-host.m4
# with its serial left intact and a comment appended. No malicious content of any
# kind. Detection keys on provenance -- a vendored file that claims to be a
# revision it is not byte-identical to -- and never on recognising a payload, which
# is the only reason the check generalises past this one incident.
set -eu

cd "$(dirname "$0")/.."
FIX="t/fixtures"
WORK="${TMPDIR:-/tmp}/srcdiff-xz-$$"
mkdir -p "$FIX" "$WORK"
trap 'rm -rf "$WORK"' EXIT

V=5.4.5
echo "fetching xz $V from upstream"
curl -sSL --max-time 180 -o "$WORK/rel.tar.gz" \
  "https://github.com/tukaani-project/xz/releases/download/v$V/xz-$V.tar.gz"
curl -sSL --max-time 180 -o "$WORK/git.tar.gz" \
  "https://codeload.github.com/tukaani-project/xz/tar.gz/refs/tags/v$V"

mkdir -p "$WORK/rel" "$WORK/git"
tar xzf "$WORK/rel.tar.gz" -C "$WORK/rel" --strip-components=1
tar xzf "$WORK/git.tar.gz" -C "$WORK/git" --strip-components=1

# Sanity: the whole premise is that build-to-host.m4 was never in git.
if [ -e "$WORK/git/m4/build-to-host.m4" ]; then
  echo "unexpected: build-to-host.m4 IS in the git tag; fixtures would be wrong" >&2
  exit 1
fi

canon=/usr/share/aclocal/build-to-host.m4
if [ ! -f "$canon" ]; then
  echo "need $canon (install gettext) -- it is the canonical copy the check compares against" >&2
  exit 1
fi

trim() {   # trim <srcdir> <destdir> <paths...>
  src="$1"; dst="$2"; shift 2
  mkdir -p "$dst"
  for p in "$@"; do
    [ -e "$src/$p" ] || continue
    ( cd "$src" && tar cf - "$p" ) | ( cd "$dst" && tar xf - )
  done
}

trim "$WORK/git" "$WORK/fx-git"  m4 configure.ac Makefile.am
trim "$WORK/rel" "$WORK/fx-rel"  m4 build-aux configure.ac Makefile.am
cp -a "$WORK/fx-rel" "$WORK/fx-tamper"

# The injection: genuine upstream macro, serial untouched, one comment appended.
cp "$canon" "$WORK/fx-tamper/m4/build-to-host.m4"
cat >> "$WORK/fx-tamper/m4/build-to-host.m4" <<'EOF'

dnl ---- INJECTED BY t/mkxzfixtures.sh, NOT MALICIOUS ----
dnl Stands in for the xz-utils 5.6.1 modification. The real file carried an
dnl obfuscated stage-0 that extracted its payload from a test fixture. This line
dnl only has to be content upstream does not have: the check tests provenance,
dnl never recognition of a payload.
EOF

pack() { ( cd "$2" && tar czf "$OLDPWD/$FIX/$1" --transform "s,^\\.,xz-$V," . ); }
pack xz-5.4.5-gittag-vendored.tar.gz   "$WORK/fx-git"
pack xz-5.4.5-release-vendored.tar.gz  "$WORK/fx-rel"
pack xz-5.4.5-tampered-vendored.tar.gz "$WORK/fx-tamper"

echo
ls -la "$FIX"
echo
echo "now: python3 t/test_srcdiff.py"
