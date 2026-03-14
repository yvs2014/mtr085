:

set -e

TMPL="package-templates"
cd "$TMPL/apk-alpine"
abuild -c
cd -
ls -lR ~/packages/"$TMPL"

