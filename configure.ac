AC_INIT([mtr], [0.85])
AC_CONFIG_SRCDIR([mtr.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_FILES([version.h.tmp:version.h.in])

# AC_PROG_CC_C99 is obsolete since autoconf-2.70
m4_version_prereq([2.70],, [AC_PROG_CC_C99])
AM_PROG_CC_C_O
AC_PROG_RANLIB

AC_ARG_ENABLE(ipv6,
	AS_HELP_STRING([--disable-ipv6], [do not enable IPv6]),
	ipv6=$enableval, ipv6=yes)
AS_IF([test "x$ipv6" = "xyes"], [AC_DEFINE([ENABLE_IPV6], [], [Define to enable IPv6])])

AC_ARG_WITH(curses,
	AS_HELP_STRING([--without-curses], [without Curses library]),
	[curses=${withval}], [curses=yes])
AM_CONDITIONAL([CURSES], [test "x$curses" = "xyes"])

AC_ARG_WITH(splitmode,
	AS_HELP_STRING([--without-splitmode], [without split-mode]),
	splitmode=${withval}], [splitmode=yes])
AM_CONDITIONAL([SPLITMODE], [test "x$splitmode" = "xyes"])
AS_IF([test "x$splitmode" = "xyes"], [AC_DEFINE([SPLITMODE], [1], [Define to enable split-mode])])

AC_ARG_WITH(unicode,
	AS_HELP_STRING([--without-unicode], [without Unicode histogram]),
	[unicode=${withval}], [unicode=yes])
AS_IF([test "x$curses" = "xno"], [unicode=no])

AS_IF([test "x$unicode" = "xyes"], [
	AC_CHECK_HEADERS([ncursesw/cursesw.h ncursesw/curses.h curses.h], break)
	AC_CHECK_HEADERS([wchar.h wctype.h locale.h langinfo.h])
	AC_SEARCH_LIBS([add_wch], [ncursesw curses],	# Ncursesw and X/Open curses provide add_wch()
		AC_DEFINE([UNICODE], [1], [Define to enable unicode]),
		AC_MSG_ERROR([No wide-character curses library found]))
	AC_SEARCH_LIBS([tgetent], [ncursesw curses termcap tinfo])	# don't leak ncursesw/curses in LIBS
	AC_SEARCH_LIBS([use_default_colors], [ncursesw curses],
		AC_DEFINE([HAVE_USE_DEFAULT_COLORS], [1], [Define this if your curses library has the use_default_colors() command.]))
	AC_DEFINE(CURSES, 1, Build with curses support)
], [
	AS_IF([test "x$curses" = "xyes"], [
	AC_CHECK_HEADERS([ncurses.h ncurses/curses.h curses.h cursesX.h], break)
	AC_SEARCH_LIBS([tgetent], [termcap tinfo])
	AC_SEARCH_LIBS([initscr], [ncurses curses cursesX],
		AC_DEFINE(CURSES, 1, Build with curses support),
		AC_MSG_WARN(Building without curses display support))
	AC_SEARCH_LIBS([use_default_colors], [ncurses curses],
		AC_DEFINE([HAVE_USE_DEFAULT_COLORS], [1], [Define this if your curses library has the use_default_colors() command.]))
])
])

AC_SEARCH_LIBS([pow], [m],, AC_MSG_ERROR(No math library found))
AC_SEARCH_LIBS([socket], [socket],, AC_MSG_ERROR(No socket library found))
AC_SEARCH_LIBS([gethostbyname], [nsl],, AC_MSG_ERROR(No nameservice library found))

AC_ARG_WITH([libidn],
	AS_HELP_STRING([--with-libidn], [IDN support (libidn)]),
	[libidn="${withval}"], [libidn=no])
AM_CONDITIONAL([LIBIDN], [test "x$libidn" = "xyes"])

AC_ARG_WITH([libasan],
	AS_HELP_STRING([--with-libasan], [build with AddressSanitizer]),
	[libasan="${withval}"], [libasan=no])
AM_CONDITIONAL([LIBASAN], [test "x$libasan" = "xyes"])

AC_ARG_WITH([ipinfo],
	AS_HELP_STRING([--without-ipinfo], [without IP-info lookup]),
	[ipinfo="${withval}"], [ipinfo=yes])
AM_CONDITIONAL([IPINFO], [test "x$ipinfo" = "xyes"])
AS_IF([test "x$ipinfo" = "xyes"], [AC_DEFINE([IPINFO], [1], [Define to enable ipinfo lookup])])

AC_ARG_WITH([graphcairo_xcb],
	AS_HELP_STRING([--with-graphcairo-xcb], [Cairo graph with XCB backend]),
	[graphcairo_xcb="${withval}"], [graphcairo_xcb=no])
AS_IF([test "x$curses" = "xno"], [graphcairo_xcb=no])
AM_CONDITIONAL([GRAPHCAIRO_XCB], [test "x$graphcairo_xcb" = "xyes"])
dnl
AC_ARG_WITH([graphcairo_xlib],
	AS_HELP_STRING([--with-graphcairo-xlib], [Cairo graph with Xlib backend]),
	[graphcairo_xlib="${withval}"], [graphcairo_xlib=no])
AS_IF([test "x$curses" = "xno"], [graphcairo_xlib=no])
AM_CONDITIONAL([GRAPHCAIRO_XLIB], [test "x$graphcairo_xlib" = "xyes"])
dnl
AM_CONDITIONAL([GRAPHCAIRO], [test "x$graphcairo_xcb" = "xyes" -o "x$graphcairo_xlib" = "xyes"])


dnl
dnl Extra output formats: csv, raw, txt, xml, json
dnl 	"csv, json" enabled by default

AC_ARG_WITH([output_csv],
	AS_HELP_STRING([--with-output-csv], [CSV output format]),
	[output_csv="${withval}"], [output_csv=yes])
AS_IF([test "x$output_csv" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_CSV], 1, [Support CSV output format])])

AC_ARG_WITH([output_raw],
	AS_HELP_STRING([--with-output-raw], [RAW output format]),
	[output_raw="${withval}"], [output_raw=no])
AS_IF([test "x$output_raw" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_RAW], 1, [Support RAW output format])])

AC_ARG_WITH([output_txt],
	AS_HELP_STRING([--with-output-txt], [TXT output format]),
	[output_txt="${withval}"], [output_txt=no])
AS_IF([test "x$output_txt" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_TXT], 1, [Support TXT output format])])

AC_ARG_WITH([output_xml],
	AS_HELP_STRING([--with-output-xml], [XML output format]),
	[output_xml="${withval}"], [output_xml=no])
AS_IF([test "x$output_xml" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_XML], 1, [Support XML output format])])

AC_ARG_WITH([output_json],
	AS_HELP_STRING([--with-output-json], [JSON output format]),
	[output_json="${withval}"], [output_json=yes])
AS_IF([test "x$output_json" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_JSON], 1, [Support JSON output format])])


dnl
dnl Add some syslog debug: net, dns, ipinfo

AC_ARG_WITH([syslog_net],
	AS_HELP_STRING([--with-syslog-net], [Enable debug: net syslog]),
	[syslog_net="${withval}"], [syslog_net=no])
AS_IF([test "x$syslog_net" != "xno"], [AC_DEFINE([LOG_NET], 1, [Enable debug: net syslog])])

AC_ARG_WITH([syslog_dns],
	AS_HELP_STRING([--with-syslog-dns], [Enable debug: dns syslog]),
	[syslog_dns="${withval}"], [syslog_dns=no])
AS_IF([test "x$syslog_dns" != "xno"], [AC_DEFINE([LOG_DNS], 1, [Enable debug: dns syslog])])

AC_ARG_WITH([syslog_ipinfo],
	AS_HELP_STRING([--with-syslog-ipinfo], [Enable debug: ipinfo syslog]),
	[syslog_ipinfo="${withval}"], [syslog_ipinfo=no])
AS_IF([test "x$syslog_ipinfo" != "xno"], [AC_DEFINE([LOG_IPINFO], 1, [Enable debug: ipinfo syslog])])


dnl don't break anything if pkg-config is absent
m4_ifndef([PKG_CHECK_MODULES], [m4_defun([PKG_CHECK_MODULES], [AC_MSG_ERROR([
  Could not locate the pkg-config automake macros, these are usually located in
    .../share/aclocal/pkg.m4
  Before running bootstrap try setting the environment variable
    ACLOCAL_PATH="/own/dir"
  or configure --without-libidn --without-graphcairo-*
])])])

PKG_PROG_PKG_CONFIG

AS_IF([test "x$graphcairo_xcb" = "xyes"], [
	AC_DEFINE([GRAPHCAIRO], [1], [Define to enable cairo graph])
	PKG_CHECK_MODULES([graphcairo], [cairo >= 1.12 pango >= 1.10 pangocairo xcb xcb-keysyms cairo-xcb], [
		LIBS="$LIBS -lm"
		AC_SUBST(graphcairo_CFLAGS)
		AC_SUBST(graphcairo_LIBS)
		AC_DEFINE([GRAPHCAIRO_XCB], [1], [Define to enable cairo XCB backend])
	])
], [
AS_IF([test "x$graphcairo_xlib" = "xyes"], [
	AC_DEFINE([GRAPHCAIRO], [1], [Define to enable cairo graph])
	PKG_CHECK_MODULES([graphcairo], [cairo pango >= 1.10 pangocairo x11 cairo-xlib], [
		LIBS="$LIBS -lm"
		AC_SUBST(graphcairo_CFLAGS)
		AC_SUBST(graphcairo_LIBS)
		AC_DEFINE([GRAPHCAIRO_XLIB], [1], [Define to enable cairo Xlib backend])
	])
])
])

AS_IF([test "x$libidn" = "xyes"], [
	PKG_CHECK_MODULES([libidn2], [libidn2], [
		AC_SUBST(libidn2_CFLAGS)
		AC_SUBST(libidn2_LIBS)
		AC_DEFINE([HAVE_LIBIDN2], [1], [Define to enable libidn2])
	], [
	PKG_CHECK_MODULES([libidn], [libidn], [
		AC_SUBST(libidn_CFLAGS)
		AC_SUBST(libidn_LIBS)
		AC_DEFINE([HAVE_LIBIDN], [1], [Define to enable libidn])
	])
	])
])

dnl Add C flags to display more warnings
AC_MSG_CHECKING(for C flags to get more warnings)
AS_IF([test "x$ac_cv_c_compiler_gnu" = "xyes"], [
	CFLAGS="$CFLAGS -Wall"
	AC_MSG_RESULT([-Wall])
], [
	AC_MSG_RESULT([none provided])
])

AC_CONFIG_HEADERS([config.h])
AH_TOP([
#ifndef CONFIG_H
#define CONFIG_H
])
AH_BOTTOM([
#endif
])

dnl AC_CONFIG_FILES([Makefile img/Makefile])
AC_CONFIG_FILES([Makefile])

dnl fix mandir
AC_CANONICAL_HOST
AS_CASE([$host_os], [freebsd*|openbsd*], [fixmandir=/usr/local], [netbsd*], [fixmandir=/usr/pkg])
AS_IF([test "x$fixmandir" != "x"], [
	AS_IF([test "x$prefix" = "xNONE"], [chkprefix=${ac_default_prefix}], [chkprefix=${prefix}])
	AS_CASE([$chkprefix], [$fixmandir], [
		AC_SUBST([mandir], [${chkprefix}/man])
		AC_MSG_NOTICE([mandir fix: $mandir])
	])
])

AC_OUTPUT

