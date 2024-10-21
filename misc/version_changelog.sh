:

set -e
LANG=C

NAME='mtr085'
TAG0='97af563'
BACKUP=yes
DISTS='noble'
META='urgency=low'
EMAIL='yvs <VSYakovetsky@gmail.com>'
CHANGELOG='debian/changelog'

[ $# -lt 1 ] && { echo "Use: $(basename $0) 'string with comment'"; exit 1; }

git_comments=
for m in "$@"; do
	git_comments="$git_comments -m \"$m\""
done
deb_comments='  * mtr085 fork with whois info, unicode, etc.'

vers="$(git rev-list --count $TAG0..HEAD)"
next=$(($vers + 1))

[ -n "$BACKUP" ] && cp "$CHANGELOG" "/tmp/$(basename $CHANGELOG).bk"
echo "$NAME ($next) $DISTS; $META\n\n$deb_comments\n\n -- $EMAIL  $(date -R)" > "$CHANGELOG"

echo "Keep in mind to do:"
echo "	git diff"
echo "	git status"
echo "	meson setup _build && meson compile -C _build && rm -rf _build"
echo "	git add ."
echo "	git commit $git_comments"
echo "	git push"

