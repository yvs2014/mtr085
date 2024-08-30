:

set -e
AUR=aur
export PKGDEST="$(pwd)/$AUR"

mkdir -p "$AUR"
cd package-templates/aur-archlinux
makepkg -cf || :
cd -
ls -l "$AUR"

