
alias build := build-meson
alias clean := clean-meson
#alias install := install-meson
#
alias meson := build-meson
alias cmake := build-cmake
alias make  := build-make
#
alias meson-build := build-meson
alias cmake-build := build-cmake
alias make-build  := build-make
#alias meson-install := install-meson
#alias cmake-install := install-cmake
#alias make-install  := install-make
alias meson-clean := clean-meson
alias cmake-clean := clean-cmake
alias make-clean  := clean-make

##
## (1) preferable
## meson
##
build-meson:
	test -d _build || meson setup _build
	meson compile -C _build
#install-meson: build-meson
#	meson install -C _build
clean-meson:
	rm -rf _build

##
## (2)
## cmake
##
build-cmake:
	test -d _build || cmake -B _build -S $(pwd)
	cmake --build _build
#install-cmake: build-cmake
#	cmake --install _build
clean-cmake:
	rm -rf _build


##
## (3) last resort
## make
##
build-make:
	autoreconf -fi
	./configure
	make
#install-make: build-make
#	make install
clean-make:
	make clean
	rm -f config.guess
	rm -f config.log
	rm -f config.status
	rm -f config.sub
	rm -f config.h
	rm -f configure~

##
## packaging
##
HOME := env('HOME')
TMPL := "package-templates"
alias debian := deb
alias arch   := aur
alias alp    := apk
alias alpine := apk

check_dep dep hint:
	@command -v {{dep}} >/dev/null || (echo ">>> '{{dep}}' is not found (hint: {{hint}})"; exit 1;)

DEB_DIR := "debs"
deb: \
(check_dep "dpkg-buildpackage" "apt install dpkg-dev" ) \
(check_dep "dh"                "apt install debhelper") \
(check_dep "pkg-config"        "apt install pkgconf"  )
	@mkdir -p "{{DEB_DIR}}"
	DEBDIR="--destdir={{DEB_DIR}}"                \
	dpkg-buildpackage -b -tc --no-sign            \
	--buildinfo-option="-u{{DEB_DIR}}"            \
	--buildinfo-file="{{DEB_DIR}}/last.buildinfo" \
	--changes-option="-u{{DEB_DIR}}"              \
	--changes-file="{{DEB_DIR}}/last.changes"
	@ls -lR "{{DEB_DIR}}"

RPM_DIR := "rpms"
rpm: (check_dep "rpmbuild" "dnf install rpm-build")
	@cd "{{TMPL}}/rpm-package" && \
	rpmbuild -ba --define "_sourcedir ../.." --define "_rpmdir ../../{{RPM_DIR}}" mtr085.spec
	@ls -lR "{{RPM_DIR}}"

AUR_DIR := "aur"
aur: (check_dep "makepkg" "it needs 'makepkg'")
	@mkdir -p "{{AUR_DIR}}"
	@cd "{{TMPL}}/aur-archlinux" && \
	makepkg -cf
	@cd -
	@ls -l "{{AUR_DIR}}"

APK_DIR := HOME + "/packages/" + TMPL
apk: (check_dep "abuild" "apk add abuild")
	@mkdir -p "{{APK_DIR}}"
	@cd "{{TMPL}}/apk-alpine" && \
	abuild -rc
	@cd -
	@ls -lR "{{APK_DIR}}"

snap: (check_dep "snapcraft" "snap install snapcraft")
	snapcraft
	@ls -l *.snap

