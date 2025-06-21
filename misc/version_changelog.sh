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
CPPDEF='#define\sGITREV\s'

[ $# -lt 1 ] && { echo "Use: $(basename "$0") 'string with comment'"; exit 1; }

git_comments=
for m in "$@"; do
	git_comments="$git_comments -m \"$m\""
done
deb_comments='  * mtr085 fork with whois info, unicode, etc.'

vers="$(git rev-list --count $TAG0..HEAD)"
next=$((vers + 1))

sed -i "s/^\($CPPDEF\).*/\1\"$next\"/" common.h

[ -n "$BACKUP" ] && cp "$CHANGELOG" "/tmp/$(basename $CHANGELOG).bk"
printf "%s (%s) %s; %s\n\n%s\n\n -- %s  %s" \
	"$NAME" "$next" "$DISTS" "$META" "$deb_comments" "$EMAIL" "$(date -R)" \
> "$CHANGELOG"

cat << EOF
Keep in mind to do:
	git diff
	git status
	just && just clean
	git add .
	git commit "$git_comments"
	git push
EOF

