
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

