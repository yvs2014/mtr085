:

set -e
AUR=aur
PKGDEST="$(pwd)/$AUR"
export PKGDEST

mkdir -p "$AUR"
cd package-templates/aur-archlinux
makepkg -cf || :
cd -
ls -l "$AUR"

