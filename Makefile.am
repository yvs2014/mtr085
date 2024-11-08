# SUBDIRS = img

NAME = mtr

man_MANS = $(NAME).8

if SUID_LAST_RESORT
sbin_PROGRAMS = $(NAME)
PROGRAM = $(DESTDIR)$(sbindir)/$(NAME)
endif
if !SUID_LAST_RESORT
bin_PROGRAMS = $(NAME)
PROGRAM = $(DESTDIR)$(bindir)/$(NAME)
endif

POSTINST_HOOK = test "`uname -s`" = "Linux" && `setcap cap_net_raw+ep $(PROGRAM)`
if SUID_LAST_RESORT
POSTINST_HOOK += || chmod u+s $(PROGRAM)
endif
install-exec-hook:
	@if test `id -u` -eq 0; then $(POSTINST_HOOK); fi

mtr_SOURCES = mtr.c common.h \
              net.c net.h \
              display.c display.h \
              report.c report.h \
              poll.c mtr-poll.h \
              aux.c aux.h

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

if DNS
if EXTRESOLV
AM_CPPFLAGS += -DBIND_8_COMPAT
mtr_LDADD += -lresolv
endif
endif

CLEANFILES = $(man_MANS)

EXCLOPTS=
if !IPV6
EXCLOPTS += 4
EXCLOPTS += 6
endif
if !MPLS
EXCLOPTS += e
endif
if !IPINFO
EXCLOPTS += l
endif
if !DNS
EXCLOPTS += n
EXCLOPTS += N
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
if !IPTOS
EXCLOPTS += q
endif

$(man_MANS): $(man_MANS).in config.h
	@cat $(man_MANS).in > $@
	@for opt in $(EXCLOPTS); do sed -i.bak "s/^\(\.ds o$$opt \"\).*/\1/" $@ ; done; rm -f $@.bak

EXTRA_DIST = SECURITY $(man_MANS).in Makefile Makefile.dist
DISTCLEANFILES = *~

