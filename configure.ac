AC_INIT([mtr], [0.85])
AC_CONFIG_SRCDIR([mtr.c])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_CONFIG_FILES([version.h.tmp:version.h.in])

AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_RANLIB

AC_CHECK_SIZEOF(unsigned char, 1)
AC_CHECK_SIZEOF(unsigned short, 2)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)

AC_CHECK_HEADERS(sys/types.h fcntl.h socket.h sys/socket.h sys/xti.h arpa/nameser_compat.h)

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
AC_CHECK_HEADERS(ncurses.h ncurses/curses.h curses.h cursesX.h, break)

# We don't refer to any symbols in termcap, but -lcurses on SunOS does.
# We have to trust the linker not to mess things up... (It should not
# pull in anything if we don't refer to anything in the lib).
AC_CHECK_LIB(termcap, tgetent)
AC_CHECK_LIB(tinfo, tgetent)

AC_CHECK_FUNC(initscr, ,
  AC_CHECK_LIB(ncurses, initscr, ,
    AC_CHECK_LIB(curses, initscr, ,
      AC_CHECK_LIB(cursesX, initscr,
	AC_DEFINE(CURSES, 1, Build with curses support),
	AC_MSG_WARN(Building without curses display support)))))

AC_SEARCH_LIBS([use_default_colors], [ncurses curses],
  AC_DEFINE(HAVE_USE_DEFAULT_COLORS, 1, [Define this if your curses library has the use_default_colors() command.]))
])
])

AC_CHECK_FUNCS(attron fcntl)

AC_CHECK_LIB(m, floor, , AC_MSG_ERROR(No math library found))

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

AC_ARG_WITH([graphcairo_xlib],
	AS_HELP_STRING([--with-graphcairo-xlib], [Cairo graph with Xlib backend]),
	[graphcairo_xlib="${withval}"], [graphcairo_xlib=no])
AS_IF([test "x$curses" = "xno"], [graphcairo_xlib=no])
AM_CONDITIONAL([GRAPHCAIRO_XLIB], [test "x$graphcairo_xlib" = "xyes"])

AM_CONDITIONAL([GRAPHCAIRO], [test "x$graphcairo_xcb" = "xyes" -o "x$graphcairo_xlib" = "xyes"])

AC_ARG_WITH([libidn],
	AS_HELP_STRING([--with-libidn], [IDN support (libidn)]),
	[libidn="${withval}"], [libidn=no])
AM_CONDITIONAL([LIBIDN], [test "x$libidn" = "xyes"])
AC_ARG_WITH([sys_getopt],
	    AS_HELP_STRING([--without-sys-getopt], [do not use your system getopt]),
	[sys_getopt="${withval}"], [sys_getopt=yes])
AM_CONDITIONAL([LOCAL_GETOPT], [test "x$sys_getopt" = "xno"])

AC_ARG_ENABLE([syslog_debug],
	AS_HELP_STRING([--enable-syslog-debug[[[=net,dns,ipinfo]]]],
		[syslog debug on (default: dns,ipinfo)]),
	[syslog_debug="${enableval}"], [syslog_debug=no])

AS_IF([test "x$syslog_debug" != "xno"], [
	AC_DEFINE([MTR_SYSLOG], [LOG_INFO], [Define syslog level])
	AS_IF([test "x$syslog_debug" = "xyes"], [
#		AC_DEFINE([LOG_NET], 1, [Enable Net module debug logging])
		AC_DEFINE([LOG_DNS], 1, [Enable DNS debug logging])
		AC_DEFINE([LOG_IPINFO], 1, [Enable IPinfo logging])
	], [AS_IF([test "x$syslog_debug" = "xnet"], [
		AC_DEFINE([LOG_NET], 1, [Enable Net debug logging])
	], [AS_IF([test "x$syslog_debug" = "xdns"], [
		AC_DEFINE([LOG_DNS], 1, [Enable DNS debug logging])
	], [AS_IF([test "x$syslog_debug" = "xipinfo"], [
		AC_DEFINE([LOG_IPINFO], 1, [Enable IPinfo logging])
	])
	])
	])
	])
])

AC_ARG_WITH([output_format],
	AS_HELP_STRING([--with-output-format[[[=csv,raw,txt,xml]]]],
		[additional output formats (default: all)]),
	[output_format="${withval}"], [output_format=no])

AS_IF([test "x$output_format" != "xno"], [
	AS_IF([test "x$output_format" = "xyes"], [
		AC_DEFINE([OUTPUT_FORMAT_CSV], 1, [Support CSV output format])
		AC_DEFINE([OUTPUT_FORMAT_RAW], 1, [Support RAW output format])
		AC_DEFINE([OUTPUT_FORMAT_TXT], 1, [Support TXT output format])
		AC_DEFINE([OUTPUT_FORMAT_XML], 1, [Support XML output format])
	], [AS_IF([test "x$output_format" = "xall"], [
		AC_DEFINE([OUTPUT_FORMAT_CSV], 1, [Support CSV output format])
		AC_DEFINE([OUTPUT_FORMAT_RAW], 1, [Support RAW output format])
		AC_DEFINE([OUTPUT_FORMAT_TXT], 1, [Support TXT output format])
		AC_DEFINE([OUTPUT_FORMAT_XML], 1, [Support XML output format])
	], [AS_IF([test "x$output_format" = "xcsv"], [
		AC_DEFINE([OUTPUT_FORMAT_CSV], 1, [Support CSV output format])
	], [AS_IF([test "x$output_format" = "xraw"], [
		AC_DEFINE([OUTPUT_FORMAT_RAW], 1, [Support RAW output format])
	], [AS_IF([test "x$output_format" = "xtxt"], [
		AC_DEFINE([OUTPUT_FORMAT_TXT], 1, [Support TXT output format])
	], [AS_IF([test "x$output_format" = "xxml"], [
		AC_DEFINE([OUTPUT_FORMAT_XML], 1, [Support XML output format])
	])
	])
	])
	])
	])
	])
])

AC_ARG_ENABLE(ipv6,
	AS_HELP_STRING([--disable-ipv6], [do not enable IPv6]),
	WANTS_IPV6=$enableval, WANTS_IPV6=yes)

m4_ifndef([PKG_CHECK_MODULES], [m4_defun([PKG_CHECK_MODULES], [AC_MSG_ERROR([
  Could not locate the pkg-config automake macros, these are usually located in
    .../share/aclocal/pkg.m4
  Before running bootstrap try setting the environment variable
    ACLOCAL_PATH="/own/dir"
  or configure --without-graphcairo-*
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
	PKG_CHECK_MODULES([libidn], [libidn], [
		AC_SUBST(libidn_CFLAGS)
		AC_SUBST(libidn_LIBS)
		AC_DEFINE([HAVE_LIBIDN], [1], [Define to enable libidn])
	])
])

AS_IF([test "x$sys_getopt" = "xyes"], [
	AC_CHECK_HEADERS([getopt.h])
	AC_CHECK_FUNCS([getopt_long], AC_DEFINE([HAVE_GETOPT_LONG]), AC_MSG_ERROR([No system getopt_long found]))
])

AC_CANONICAL_HOST
case "$host_os" in
  linux*)
    AC_DEFINE(_DEFAULT_SOURCE, 1, [enable "default" definitions (since glibc 2.20)])
  ;;
  solaris*)
    AC_DEFINE(BSD_COMP, 1, [enable BSD compatibility])
  ;;
  netbsd*)
    AC_DEFINE(NETBSD_CURSES, 1, [NetBSD: a hybrid of BSD-curses with X/Open curses])
  ;;
esac

AC_CHECK_FUNC(socket, ,
  AC_CHECK_LIB(socket, socket, , AC_MSG_ERROR(No socket library found)))

AC_CHECK_FUNC(gethostbyname, ,
  AC_CHECK_LIB(nsl, gethostbyname, , AC_MSG_ERROR(No nameservice library found)))

#AC_CHECK_FUNC(res_init, ,
#  AC_CHECK_LIB(bind, res_init, ,
#   AC_CHECK_LIB(resolv, res_init, , AC_MSG_ERROR(No resolver library found))))

AC_CHECK_FUNCS(seteuid)
#  AC_CHECK_FUNC(setuid, , AC_MSG_ERROR (I Need either seteuid or setuid))

#AC_CHECK_FUNC(res_mkquery, ,
#  AC_CHECK_LIB(bind, res_mkquery, ,
#   AC_CHECK_LIB(resolv, res_mkquery, ,
#     AC_CHECK_LIB(resolv, __res_mkquery, , AC_MSG_ERROR(No resolver library found)))))

# See if a library is needed for res_mkquery and if so put it in RESOLV_LIBS
RESOLV_LIBS=
AC_SUBST(RESOLV_LIBS)
AC_DEFUN([LIBRESOLVTEST_SRC], [
AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <resolv.h>
]], [[
int (*res_mkquery_func)(int,...) = (int (*)(int,...))res_mkquery;
(void)(*res_mkquery_func)(0);
]])])
AC_MSG_CHECKING([whether library required for res_mkquery])
RESOLV_LIB_NONE=
AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
	[AC_MSG_RESULT([no])
	RESOLV_LIB_NONE=yes],
	[AC_MSG_RESULT([yes])])
if test "x$RESOLV_LIB_NONE" = "x"; then
	AC_MSG_CHECKING([for res_mkquery in -lbind])
	STASH_LIBS="$LIBS"
	LIBS="$STASH_LIBS -lbind"
	AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
		[AC_MSG_RESULT([yes])
		RESOLV_LIBS=-lbind],
		[AC_MSG_RESULT([no])])
	if test "x$RESOLV_LIBS" = "x"; then
		AC_MSG_CHECKING([for res_mkquery in -lresolv])
		LIBS="$STASH_LIBS -lresolv"
		AC_LINK_IFELSE([LIBRESOLVTEST_SRC],
			[AC_MSG_RESULT([yes])
			RESOLV_LIBS=-lresolv],
			[AC_MSG_RESULT([no])
                        AC_MSG_ERROR(No resolver library found)])
	fi
	LIBS="$STASH_LIBS"
fi

USES_IPV6=
AC_CHECK_FUNC(getaddrinfo,
[if test "$WANTS_IPV6" = "yes"; then
	AC_DEFINE([ENABLE_IPV6], [], [Define to enable IPv6])
	USES_IPV6=yes
fi])

AC_DEFUN([NEED_RES_STATE_EXT_TEST_SRC], [
AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <resolv.h>
#ifdef __GLIBC__
#define RESEXTIN6(r,i) (*(r._u._ext.nsaddrs[i]))
#else
#define RESEXTIN6(r,i) (r._u._ext.ext->nsaddrs[i].sin6)
#endif
]], [[
struct __res_state res;
return RESEXTIN6(res,0).sin6_addr.s6_addr[0];
]])])
AC_DEFUN([DEFINE_RES_STATE_EXT_TEST_SRC], [
AC_LANG_PROGRAM([[
#include <netinet/in.h>
#include <resolv.h>
#ifdef __GLIBC__
#define RESEXTIN6(r,i) (*(r._u._ext.nsaddrs[i]))
#else
#define RESEXTIN6(r,i) (r._u._ext.ext->nsaddrs[i].sin6)
struct __res_state_ext {
	union res_sockaddr_union nsaddrs[MAXNS];
	struct sort_list {
		int     af;
		union {
			struct in_addr  ina;
			struct in6_addr in6a;
		} addr, mask;
	} sort_list[MAXRESOLVSORT];
	char nsuffix[64];
	char nsuffix2[64];
};
#endif
]], [[
struct __res_state res;
return RESEXTIN6(res,0).sin6_addr.s6_addr[0];
]])])
if test "x$USES_IPV6" = "xyes"; then
	AC_MSG_CHECKING([whether __res_state_ext needs to be defined])
	AC_COMPILE_IFELSE([NEED_RES_STATE_EXT_TEST_SRC],
		[AC_MSG_RESULT([no])],
		[AC_MSG_RESULT([yes])
		AC_MSG_CHECKING([whether provided __res_state_ext definition can be compiled])
		AC_COMPILE_IFELSE([DEFINE_RES_STATE_EXT_TEST_SRC],
			[AC_MSG_RESULT([yes])
			AC_DEFINE(NEED_RES_STATE_EXT, 1, [Define if struct __res_state_ext needs to be defined.])],
			[AC_MSG_RESULT([no])
			AC_MSG_ERROR(Need definition for struct __res_state_ext but unable to define it.)])])
fi

AC_CHECK_TYPE(socklen_t, AC_DEFINE([HAVE_SOCKLEN_T], [], [Define if your system has socklen_t]) , , [[
#include <netinet/in.h>
#ifdef HAVE_SOCKET_H
#include <socket.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
]])

AC_CHECK_TYPE(struct in_addr, AC_DEFINE([HAVE_STRUCT_INADDR], [], [Define if you have struct in_addr]), , [[
#include <netinet/in.h>
]])

dnl Add C flags to display more warnings
AC_MSG_CHECKING(for C flags to get more warnings)
ac_save_CFLAGS="$CFLAGS"
if test "x$ac_cv_c_compiler_gnu" = "xyes" ; then
  extra_CFLAGS="-Wall"
else
  dnl Vendor supplied C compilers are a bit tricky
  case "$host_os" in
    dnl SGI IRIX with the MipsPRO C compiler
    irix*)
      CFLAGS="$CFLAGS -fullwarn"
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[printf("test");]])],[extra_CFLAGS="-fullwarn"],[])
      ;;

    dnl SunOS 4.x with the SparcWorks(?) acc compiler
    sunos*)
        if "$CC" = "acc" ; then
          CFLAGS="$CFLAGS -vc"
          AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>]], [[printf("test");]])],[extra_CFLAGS="-vc"],[])
        fi
      ;;

    dnl Unknown, do nothing
    *)
      extra_CFLAGS="none"
      ;;
  esac
fi
CFLAGS="$ac_save_CFLAGS"
if test "$extra_CFLAGS" = "none" ; then
  AC_MSG_RESULT(none)
else
  CFLAGS="$CFLAGS $extra_CFLAGS"
  AC_MSG_RESULT($extra_CFLAGS)
fi




AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile img/Makefile])
AC_OUTPUT

