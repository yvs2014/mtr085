SUBDIRS = img

sbin_PROGRAMS = mtr
man_MANS = mtr.8
install-exec-hook: 
	chmod u+s $(DESTDIR)$(sbindir)/mtr

mtr_SOURCES = mtr.c \
              net.c net.h \
              dns.c dns.h \
              raw.c raw.h \
              display.c display.h \
              report.c report.h \
              select.c select.h

nodist_mtr_SOURCES = version.h

AM_CPPFLAGS =
mtr_LDADD = $(RESOLV_LIBS)

if GTK
mtr_SOURCES += gtk/gtk.c gtk/mtr-gtk.h
AM_CPPFLAGS += -Igtk
endif

if CURSES
mtr_SOURCES += curses.c mtr-curses.h
endif

if SPLITMODE
mtr_SOURCES += split.c split.h
endif

if LOCAL_GETOPT
mtr_SOURCES += getopt/getopt.c getopt/getopt1.c getopt/getopt.h
AM_CPPFLAGS += -Igetopt
endif

if IPINFO
mtr_SOURCES += asn.c asn.h
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
libgraphcairo_a_CPPFLAGS = @graphcairo_CFLAGS@ -Igraphcairo
AM_CPPFLAGS += -Igraphcairo
mtr_LDADD += @graphcairo_LIBS@
mtr_SOURCES += $(graphcairo_a_SOURCES)
endif

if LIBIDN
AM_CPPFLAGS += @libidn_CFLAGS@
mtr_LDADD += @libidn_LIBS@
endif

CLEANFILES = version.h
BUILT_SOURCES = version.h

version.h: version.h.tmp Makefile $(mtr_SOURCES)
	@cat version.h.tmp > $@; \
	if [ -d .git ] && [ -n "$$(which git)" ]; then \
	  xver="+git:$$(git rev-list -n1 --abbrev=8 --abbrev-commit HEAD)"; \
	  sed \
	    -e "/#define *MTR_VERSION */{s/\"\([^\"]*\)\"/\"\1$$xver\"/;}" \
	    version.h.tmp > $@; \
	fi;

EXTRA_DIST = SECURITY mtr.8 Makefile Makefile.dist
distclean-local:
	(sleep 3; cp Makefile.dist Makefile) &
	rm -f *.orig

DISTCLEANFILES = *~

