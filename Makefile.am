# SUBDIRS = img

sbin_PROGRAMS = mtr
man_MANS = mtr.8
install-exec-hook:
	test "`uname -s`" = "Linux" && `setcap cap_net_raw+ep $(DESTDIR)$(sbindir)/mtr` || chmod u+s $(DESTDIR)$(sbindir)/mtr

mtr_SOURCES = mtr.c mtr.h \
              macros.h \
              net.c net.h \
              display.c display.h \
              report.c report.h \
              poll.c mtr-poll.h

nodist_mtr_SOURCES = version.h

AM_CPPFLAGS =
mtr_LDADD = $(RESOLV_LIBS)

if DNS
mtr_SOURCES += dns.c dns.h
endif

if CURSES
mtr_SOURCES += curses.c mtr-curses.h
endif

if SPLITMODE
mtr_SOURCES += split.c split.h
endif

if IPINFO
mtr_SOURCES += ipinfo.c ipinfo.h
endif

if GRAPHS
mtr_LDADD += libgraphcairo.a
noinst_LIBRARIES = libgraphcairo.a
libgraphcairo_a_SOURCES = \
	graphcairo/graphcairo.c graphcairo/graphcairo.h \
	graphcairo/graphcairo-mtr.c graphcairo/graphcairo-mtr.h \
	graphcairo/graphcairo-backend.h
if GRAPHS_XCB
libgraphcairo_a_SOURCES += graphcairo/graphcairo-xcb.c
endif
if GRAPHS_XLIB
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

CLEANFILES = version.h mtr.8
BUILT_SOURCES = version.h

version.h: version.h.tmp Makefile $(mtr_SOURCES)
	@cat version.h.tmp > $@; \
	if [ -d .git ] && [ -n "$$(which git)" ]; then \
	  xver=".$$(git rev-list HEAD | sed '/^97af563/q' | sed -n '$$=')"; \
	  sed -e "/#define *MTR_VERSION */{s/\"\([^\"]*\)\"/\"\1$$xver\"/;}" \
	    version.h.tmp > $@; \
	fi;

EXCLOPTS=
if !IPV6
EXCLOPTS += 6
endif
if !MPLS
EXCLOPTS += e
endif
if !GRAPHS
EXCLOPTS += g
endif
if !DNS
EXCLOPTS += n
endif
if !OUTPUTFMT
EXCLOPTS += o
endif
if !OUTPUT_RAW
EXCLOPTS += or
endif
if !OUTPUT_TXT
EXCLOPTS += ot
endif
if !OUTPUT_CSV
EXCLOPTS += oc
endif
if !OUTPUT_JSON
EXCLOPTS += oj
endif
if !OUTPUT_XML
EXCLOPTS += ox
endif
if !SPLITMODE
EXCLOPTS += p
endif
if !IPINFO
EXCLOPTS += y
endif

mtr.8: mtr.8.in config.h
	@cat mtr.8.in > $@
	@for opt in $(EXCLOPTS); do sed -i.bak "s/^\(\.ds o$$opt \"\).*/\1/" $@ ; done; rm -f $@.bak

EXTRA_DIST = SECURITY mtr.8.in Makefile Makefile.dist
DISTCLEANFILES = *~

