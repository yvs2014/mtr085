:

set -e

TMPL="package-templates"
cd "$TMPL/apk-alpine"
abuild -rc
cd -
ls -lR ~/packages/"$TMPL"

