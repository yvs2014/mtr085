:

set -e
LANG=C

NAME='mtr085'
TAG0='97af563'
BACKUP=yes
DISTS='lunar mantic'
META='urgency=low'
EMAIL='<VSYakovetsky@gmail.com>'

CHANGELOG='debian/changelog'
FILE1='snapcraft.yaml'
PATT1='version:'


[ $# -lt 1 ] && { echo "Use: $(basename $0) 'string with comment'"; exit 1; }

git_comments=
chl_comments=
for m in "$@"; do
	git_comments="$git_comments -m \"$m\""
	chl_comments="$chl_comments\n  "'*'" $m"
done


[ -n "$TAG0" ] && { fltr=sed; fargs="/^$TAG0/q"; } || fltr=cat

vers="$(git rev-list HEAD | $fltr $fargs | sed -n '$=')"
next=$(($vers + 1))

[ -n "$BACKUP" ] && cp "$FILE1" "/tmp/$(basename $$FILE1).bk"
sed -i "s/^\($PATT1\).*/\1 \'$next\'/" $FILE1
[ -n "$BACKUP" ] && cp "$CHANGELOG" "/tmp/$(basename $CHANGELOG).bk"
echo "$NAME ($next) $DISTS; $META\n$chl_comments\n\n -- maintainer $EMAIL  $(date -R)" > "$CHANGELOG"

echo "Keep in mind to do:"
echo "	git diff"
echo "	git status"
echo "	git add ."
echo "	git commit $git_comments"
echo "	git push"

