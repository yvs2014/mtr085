# SUBDIRS = img

sbin_PROGRAMS = mtr
man_MANS = mtr.8
install-exec-hook:
	chmod u+s $(DESTDIR)$(sbindir)/mtr

mtr_SOURCES = mtr.c \
              net.c net.h \
              dns.c dns.h \
              display.c display.h \
              report.c report.h \
              select.c select.h

nodist_mtr_SOURCES = version.h

AM_CPPFLAGS =
mtr_LDADD = $(RESOLV_LIBS)

if CURSES
mtr_SOURCES += curses.c mtr-curses.h
endif

if SPLITMODE
mtr_SOURCES += split.c split.h
endif

if IPINFO
mtr_SOURCES += ipinfo.c ipinfo.h
endif

if GRAPHCAIRO
mtr_LDADD += libgraphcairo.a
noinst_LIBRARIES = libgraphcairo.a
libgraphcairo_a_SOURCES = \
	graphcairo/graphcairo.c graphcairo/graphcairo.h \
	graphcairo/graphcairo-mtr.c graphcairo/graphcairo-mtr.h \
	graphcairo/graphcairo-backend.h
if GRAPHCAIRO_XCB
libgraphcairo_a_SOURCES += graphcairo/graphcairo-xcb.c
endif
if GRAPHCAIRO_XLIB
libgraphcairo_a_SOURCES += graphcairo/graphcairo-xlib.c
endif
libgraphcairo_a_CPPFLAGS = @graphcairo_CFLAGS@ -I.
AM_CPPFLAGS += -Igraphcairo
mtr_LDADD += @graphcairo_LIBS@
mtr_SOURCES += $(graphcairo_a_SOURCES)
endif

if LIBIDN
AM_CPPFLAGS += @libidn_CFLAGS@ @libidn2_CFLAGS@
mtr_LDADD += @libidn_LIBS@ @libidn2_LIBS@
endif

AM_CFLAGS	= -fcommon	# GCC-10

if LIBASAN
AM_CFLAGS	+= -fno-omit-frame-pointer
AM_CFLAGS	+= -fsanitize=undefined
AM_CFLAGS	+= -fsanitize=address
endif

CLEANFILES = version.h
BUILT_SOURCES = version.h

version.h: version.h.tmp Makefile $(mtr_SOURCES)
	@cat version.h.tmp > $@; \
	if [ -d .git ] && [ -n "$$(which git)" ]; then \
	  xver=".$$(git rev-list HEAD | sed '/^97af563/q' | sed -un '$$=')"; \
	  sed \
	    -e "/#define *MTR_VERSION */{s/\"\([^\"]*\)\"/\"\1$$xver\"/;}" \
	    version.h.tmp > $@; \
	fi;

EXTRA_DIST = SECURITY mtr.8 Makefile Makefile.dist
DISTCLEANFILES = *~

