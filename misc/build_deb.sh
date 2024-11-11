:

# build depends on: dpkg-dev devscripts debhelper
chk_cmd() {
  command -v "$1" >/dev/null && return
  echo "FAIL: '$1' is mandatory for packaging, please install '$2'"
  exit 1
}
chk_cmd dpkg-buildpackage dpkg-dev
chk_cmd dch devscripts
chk_cmd dh debhelper

set -e
rev="$(git rev-list HEAD | sed '/^97af563/q' | sed -n '$=')"
arch="$(dpkg-architecture -qDEB_BUILD_ARCH)"
dist="$(lsb_release -cs)"
name="mtr085"
ddir="debs"
nra="$ddir/${name}_${rev}_$arch"
chf="debian/changelog"

command -v lsb_release >/dev/null && \
lsb_release -i 2>/dev/null | grep -q Debian && \
lsb_release -r 2>/dev/null | grep '\s9\.' && \
  cp debian/autoconf/* debian/

mkdir -p "$ddir"
rm -f "$chf.tmp"
dch --create -c "$chf.tmp" --package="$name" -v "$rev" -D "$dist" -u "low" -M \
  "$name fork with whois info, unicode, etc."

mv "$chf.tmp" "$chf"

bi_file="$nra.buildinfo"
ch_file="$nra.changes"
dpkg-buildpackage --help | grep -q buildinfo-file && \
  BOUT="--buildinfo-file=$bi_file" COUT="--changes-file=$ch_file" || \
  BOUT="--buildinfo-option=-O$bi_file" COUT="--changes-option=-O$ch_file" DH_OPTIONS="--destdir=$ddir"

export DEBDIR="--destdir=$ddir"
dpkg-buildpackage -b -tc --no-sign \
  --buildinfo-option="-u$ddir" $BOUT \
  --changes-option="-u$ddir" $COUT && \
  (echo "\nPackages in $ddir/:"; ls -l "$ddir")

