AC_INIT([mtr], [0.85])
AC_CONFIG_SRCDIR([mtr.c])
AC_PROG_RANLIB
AC_CHECK_PROG(GIT, [git], [yes])
AS_IF([test "x$GIT" = "xyes"], AC_DEFINE([GITREV],
	["m4_esyscmd_s([git rev-list --count 97af563..HEAD])"], [git revision number]))

AM_INIT_AUTOMAKE([foreign nostdinc subdir-objects -Wall -Werror silent-rules])
AM_SILENT_RULES([yes])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

# don't complain on AC_PROG_CC_C99 with autoconf newer than 2.70
m4_version_prereq([2.70],, [AC_PROG_CC_C99])
AM_PROG_CC_C_O

m4_ifdef([AX_CHECK_COMPILE_FLAG],
	[AX_CHECK_COMPILE_FLAG([-std=gnu2x], [AX_APPEND_FLAG([-std=gnu2x])],
	[AX_CHECK_COMPILE_FLAG([-std=gnu17], [AX_APPEND_FLAG([-std=gnu17])],
	[AX_CHECK_COMPILE_FLAG([-std=gnu11], [AX_APPEND_FLAG([-std=gnu11])],
	[AX_CHECK_COMPILE_FLAG([-std=gnu99], [AX_APPEND_FLAG([-std=gnu99])],
	)]
	)]
	)]
	)]
)

AC_CHECK_HEADERS([netdb.h], AC_DEFINE(HAVE_NETDB_H, 1))
AC_CHECK_HEADERS([sys/param.h], AC_DEFINE(HAVE_SYS_PARAM_H, 1))
AC_CHECK_HEADERS([bsd/stdlib.h], AC_DEFINE(HAVE_BSD_STDLIB_H, 1))

AC_SEARCH_LIBS([pow], [m],, AC_MSG_ERROR(No math library found))
AC_SEARCH_LIBS([warnx], [bsd],, AC_MSG_ERROR(No bsd err/warn library found))
AC_SEARCH_LIBS([socket], [socket network],, AC_MSG_ERROR(No socket library found))
AC_CHECK_FUNC([strlcpy], AC_DEFINE(HAVE_STRLCPY, 1, [Define if strlcpy exists]),
	AC_SEARCH_LIBS([strlcpy], [bsd], [AC_DEFINE(HAVE_STRLCPY, 1)]))
AC_CHECK_FUNC([arc4random_uniform], AC_DEFINE(HAVE_ARC4RANDOM_UNIFORM, 1, [Define if arc4random_uniform exists]),
	AC_SEARCH_LIBS([arc4random_uniform], [bsd], [AC_DEFINE(HAVE_ARC4RANDOM_UNIFORM, 1)]))
AC_CHECK_FUNC([ctime_r], AC_DEFINE(HAVE_CTIME_R, 1, [Define if ctime_r exists]))
AC_CHECK_FUNC([localtime_r], AC_DEFINE(HAVE_LOCALTIME_R, 1, [Define if localtime_r exists]))

AC_ARG_ENABLE([ipv6],
	AS_HELP_STRING([--disable-ipv6], [Do not enable IPv6]),
	[ipv6=${enableval}], [ipv6=yes])
AM_CONDITIONAL([IPV6], [test "x$ipv6" = "xyes"])
AS_IF([test "x$ipv6" = "xyes"], [AC_DEFINE([ENABLE_IPV6], [], [Define to enable IPv6])])

AC_ARG_WITH(splitmode,
	AS_HELP_STRING([--without-splitmode], [without split-mode]),
	splitmode=${withval}, [splitmode=yes])
AM_CONDITIONAL([SPLITMODE], [test "x$splitmode" = "xyes"])
AS_IF([test "x$splitmode" = "xyes"], [AC_DEFINE([SPLITMODE], [1], [Define to enable split-mode])])

AC_ARG_WITH(curses,
	AS_HELP_STRING([--without-curses], [without Curses library]),
	[curses=${withval}], [curses=yes])
AM_CONDITIONAL([CURSES], [test "x$curses" = "xyes"])
_unicode="no"
AS_IF([test "x$curses" = "xyes"], [
	AC_DEFINE(CURSESMODE, 1, Build with curses support)
	AC_CHECK_HEADERS([ncursesw/ncurses.h ncursesw/curses.h ncurses/ncurses.h ncurses/curses.h ncurses.h curses.h], break)
	_curses_libs="ncursesw ncurses curses tinfo"
	AC_SEARCH_LIBS([use_default_colors], [$_curses_libs],
		AC_DEFINE([HAVE_USE_DEFAULT_COLORS], [1], [Define this if curses library has use_default_colors()]))
	AC_ARG_WITH(unicode,
		AS_HELP_STRING([--without-unicode], [without Unicode histogram]),
		[unicode=${withval}], [unicode=yes])
	AS_IF([test "x$unicode" = "xyes"], [
		AC_CHECK_HEADERS([wchar.h wctype.h locale.h langinfo.h])
		AC_SEARCH_LIBS([add_wch], [$_curses_libs], [
			AC_DEFINE([WITH_UNICODE], [1], [Define to enable unicode])
			_unicode="yes"],
		AC_MSG_ERROR([Wide-character curses library not found]))
	])
])

AC_ARG_ENABLE([dns],
	AS_HELP_STRING([--disable-dns], [Do not enable DNS]),
	[dns=${enableval}], [dns=yes])
AM_CONDITIONAL([DNS], [test "x$dns" = "xyes"])

AC_CANONICAL_HOST
AS_CASE([$host_os], [darwin*], [macos=yes])
AM_CONDITIONAL([EXTRESOLV], [test "x$macos" = "xyes"])

AS_IF([test "x$dns" = "xyes"], [
	AC_DEFINE([ENABLE_DNS], [], [Define to enable DNS])
	AC_HEADER_RESOLV
	AC_SEARCH_LIBS([gethostbyaddr], [nsl],, AC_MSG_ERROR(No nameservice library found))
	AC_SEARCH_LIBS([dn_expand], [resolv],, AC_SEARCH_LIBS([__dn_expand], [resolv],, AC_MSG_ERROR(No resolv found)))
	dnl res_xxx is resolved via macros on MacOS, so let's suggest some mkquery() is present there unconditionaly
	AS_IF([test "x$macos" = "xyes"], [AC_DEFINE([HAVE_RES_NMKQUERY], [1], [Define this if res_nmkquery() is present])], true, [
	AC_SEARCH_LIBS([res_nmkquery], [resolv],
		AC_DEFINE([HAVE_RES_NMKQUERY], [1], [Define this if res_nmkquery() is present]),
		AC_SEARCH_LIBS([__res_nmkquery], [resolv],
			AC_DEFINE([HAVE_RES_NMKQUERY], [1], [Define this if res_nmkquery() is present]),
			AC_SEARCH_LIBS([res_mkquery], [resolv],, AC_MSG_ERROR(No resolv found))))
	])
])

AC_ARG_WITH([libasan],
	AS_HELP_STRING([--with-libasan], [build with AddressSanitizer]),
	[libasan="${withval}"], [libasan=no])
AM_CONDITIONAL([LIBASAN], [test "x$libasan" = "xyes"])

AC_ARG_WITH(libcap,
	AS_HELP_STRING([--without-libcap], [without Linux capabilities]),
	[libcap=${withval}], [libcap=yes])
AS_IF([test "x$libcap" = "xyes"], [
	AC_SEARCH_LIBS([cap_set_flag], [cap],
		AC_DEFINE(LIBCAP, 1, [Build with linux capabilities]),
		AC_MSG_ERROR(Linux capability library not found))
	])

AC_ARG_ENABLE([suid_last_resort],
	AS_HELP_STRING([--enable-suid-last-resort], [install with suid bit unless setcap is present]),
	[suid_last_resort="${enableval}"], [suid_last_resort=no])
AM_CONDITIONAL([SUID_LAST_RESORT], [test "x$suid_last_resort" = "xyes"])

AC_ARG_WITH([mpls],
	AS_HELP_STRING([--with-mpls], [build with MPLS decoding]),
	[mpls="${withval}"], [mpls=yes])
AM_CONDITIONAL([MPLS], [test "x$mpls" = "xyes"])
AS_IF([test "x$mpls" = "xyes"], [AC_DEFINE([WITH_MPLS], [1], [Define to support MPLS decoding])])

AC_ARG_WITH([ipinfo],
	AS_HELP_STRING([--without-ipinfo], [without IP-info lookup]),
	[ipinfo="${withval}"], [ipinfo=yes])
AM_CONDITIONAL([IPINFO], [test "x$ipinfo" = "xyes"])
AS_IF([test "x$ipinfo" = "xyes"], [AC_DEFINE([WITH_IPINFO], [1], [Define to enable ipinfo lookup])])

# Extra output formats: raw, txt, csv, json, xml
# 	"txt, csv, json" are enabled by default, "raw, xml" are disabled

AC_ARG_WITH([output_raw],
	AS_HELP_STRING([--with-output-raw], [RAW output format]),
	[output_raw="${withval}"], [output_raw=no])
AM_CONDITIONAL([OUTPUT_RAW], [test "x$output_raw" = "xyes"])
AS_IF([test "x$output_raw" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_RAW], 1, [Support RAW output format])])

AC_ARG_WITH([output_txt],
	AS_HELP_STRING([--with-output-txt], [TXT output format]),
	[output_txt="${withval}"], [output_txt=yes])
AM_CONDITIONAL([OUTPUT_TXT], [test "x$output_txt" = "xyes"])
AS_IF([test "x$output_txt" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_TXT], 1, [Support TXT output format])])

AC_ARG_WITH([output_csv],
	AS_HELP_STRING([--with-output-csv], [CSV output format]),
	[output_csv="${withval}"], [output_csv=yes])
AM_CONDITIONAL([OUTPUT_CSV], [test "x$output_csv" = "xyes"])
AS_IF([test "x$output_csv" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_CSV], 1, [Support CSV output format])])

AC_ARG_WITH([output_json],
	AS_HELP_STRING([--with-output-json], [JSON output format]),
	[output_json="${withval}"], [output_json=yes])
AM_CONDITIONAL([OUTPUT_JSON], [test "x$output_json" = "xyes"])
AS_IF([test "x$output_json" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_JSON], 1, [Support JSON output format])])

AC_ARG_WITH([output_xml],
	AS_HELP_STRING([--with-output-xml], [XML output format]),
	[output_xml="${withval}"], [output_xml=yes])
AM_CONDITIONAL([OUTPUT_XML], [test "x$output_xml" = "xyes"])
AS_IF([test "x$output_xml" != "xno"], [AC_DEFINE([OUTPUT_FORMAT_XML], 1, [Support XML output format])])

AM_CONDITIONAL([OUTPUTFMT], [test "x$output_raw" = "xyes" -o "x$output_txt" = "xyes" \
	-o "x$output_csv" = "xyes" -o "x$output_json" = "xyes" -o "x$output_xml" = "xyes"])

# Add some development options:
#   syslog debug: poll, net, dns, ipinfo
#   gcc static analyzer [clang note: scan-build can be used as an option]

AC_ARG_ENABLE([analyzer],
	AS_HELP_STRING([--enable-analyzer], [enable static analyzer]),
	[analyzer="${withval}"], [analyzer=no])

AC_ARG_WITH([syslog_poll],
	AS_HELP_STRING([--with-syslog-poll], [Enable debug: poll syslog]),
	[syslog_poll="${withval}"], [syslog_poll=no])
AS_IF([test "x$syslog_poll" != "xno"], [AC_DEFINE([LOG_POLL], 1, [Enable debug: poll syslog])])

AC_ARG_WITH([syslog_net],
	AS_HELP_STRING([--with-syslog-net], [Enable debug: net syslog]),
	[syslog_net="${withval}"], [syslog_net=no])
AS_IF([test "x$syslog_net" != "xno"], [AC_DEFINE([LOG_NET], 1, [Enable debug: net syslog])])

AS_IF([test "x$dns" = "xyes"], [
	AC_ARG_WITH([syslog_dns],
		AS_HELP_STRING([--with-syslog-dns], [Enable debug: dns syslog]),
		[syslog_dns="${withval}"], [syslog_dns=no])
	AS_IF([test "x$syslog_dns" != "xno"], [AC_DEFINE([LOG_DNS], 1, [Enable debug: dns syslog])])
])

AS_IF([test "x$ipinfo" = "xyes"], [
	AC_ARG_WITH([syslog_ipinfo],
		AS_HELP_STRING([--with-syslog-ipinfo], [Enable debug: ipinfo syslog]),
		[syslog_ipinfo="${withval}"], [syslog_ipinfo=no])
	AS_IF([test "x$syslog_ipinfo" != "xno"], [AC_DEFINE([LOG_IPINFO], 1, [Enable debug: ipinfo syslog])])
])

need_libidn="no"
AC_MSG_CHECKING([for AI_IDN macro])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
#endif
#include <netdb.h>
#ifndef AI_IDN
#error no AI_IDN
#endif
]])], [aiidn="yes"], [aiidn="no"])
AS_IF([test "x$aiidn" = "xyes"], AC_MSG_RESULT([found]), AC_MSG_RESULT([none]))

AS_IF([test "x$aiidn" != "xyes"], [
	m4_ifdef([PKG_CHECK_MODULES], [
		PKG_PROG_PKG_CONFIG
		PKG_CHECK_MODULES([libidn2], [libidn2], [
			AC_DEFINE([LIBIDN2], [1], [Define to enable libidn2])
			AC_SUBST(libidn2_CFLAGS)
			AC_SUBST(libidn2_LIBS)
			need_libidn="yes"
		], [
		PKG_CHECK_MODULES([libidn], [libidn], [
			AC_DEFINE([LIBIDN], [1], [Define to enable libidn])
			AC_SUBST(libidn_CFLAGS)
			AC_SUBST(libidn_LIBS)
			need_libidn="yes"
		])])
	], [
		AC_CHECK_HEADER([idn2.h], AC_CHECK_LIB([idn2], [idn2_strerror], [
			AC_DEFINE([LIBIDN2], [1], [Define to enable libidn2])
			AC_SUBST(libidn2_CFLAGS)
			AC_SUBST(libidn2_LIBS, "-lidn2")
			need_libidn="yes" ]))
		AS_IF([test "x$need_libidn" != "xyes"], [
		AC_CHECK_HEADER([idn2/idn2.h], AC_CHECK_LIB([idn2], [idn2_strerror], [
			AC_DEFINE([LIBIDN2], [1], [Define to enable libidn2])
			AC_DEFINE([HAVE_IDN2_IDN2_H], [1], [idn2 header])
			AC_SUBST(libidn2_CFLAGS)
			AC_SUBST(libidn2_LIBS, "-lidn2")
			need_libidn="yes" ]))
		])
		AS_IF([test "x$need_libidn" != "xyes"], [
		AC_CHECK_HEADER([idna.h], AC_CHECK_LIB([idn], [idna_strerror], [
			AC_DEFINE([LIBIDN], [1], [Define to enable libidn])
			AC_SUBST(libidn_CFLAGS)
			AC_SUBST(libidn_LIBS, "-lidn")
			need_libidn="yes" ]))
		])
	])
])
AM_CONDITIONAL([LIBIDN], [test "x$need_libidn" = "xyes"])

AC_MSG_CHECKING([for IP_TOS macro])
AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <netinet/in.h>
#ifndef IP_TOS
#error no IP_TOS
#endif
]])], [iptos="yes"], [iptos="no"])
AS_IF([test "x$iptos" = "xyes"], AC_MSG_RESULT([found]), AC_MSG_RESULT([none]))
AM_CONDITIONAL([IPTOS], [test "x$iptos" = "xyes"])

# Extra compiler flags
# Note, AX_CHECK_COMPILE_FLAG comes from autoconf-archive
m4_ifdef([AX_CHECK_COMPILE_FLAG], [
	AX_CHECK_COMPILE_FLAG([-Wall], [CFLAGS="$CFLAGS -Wall"])
	AS_IF([test "x$analyzer" != "xno"], AX_CHECK_COMPILE_FLAG([-fanalyzer], [CFLAGS="$CFLAGS -fanalyzer"]))
], [ # at least check GNU C compat for -Wall option
	AC_MSG_CHECKING([for C flags to get more warnings])
	AS_IF([test "x$ac_cv_c_compiler_gnu" = "xyes"], [
		CFLAGS="$CFLAGS -Wall"
		AC_MSG_RESULT([-Wall])
	], [AC_MSG_RESULT([none])])
])

_option_list=""
AS_IF([test "x$libcap" = "xyes"],    [_option_list="$_option_list +CAP"],     [_option_list="$_option_list -CAP"])
AS_IF([test "x$curses" = "xyes"],    [_option_list="$_option_list +CURSES"],  [_option_list="$_option_list -CURSES"])
AS_IF([test "x$_unicode" = "xyes"],  [_option_list="$_option_list +UNICODE"], [_option_list="$_option_list -UNICODE"])
AS_IF([test "x$dns" = "xyes"],       [_option_list="$_option_list +DNS"],     [_option_list="$_option_list -DNS"])
AS_IF([test "x$aiidn" = "xyes" -o "x$need_libidn" = "yes"],
	[_option_list="$_option_list +IDN"], [_option_list="$_option_list -IDN"])
AS_IF([test "x$ipinfo" = "xyes"],    [_option_list="$_option_list +IPINFO"],  [_option_list="$_option_list -IPINFO"])
AS_IF([test "x$splitmode" = "xyes"], [_option_list="$_option_list +SPLIT"],   [_option_list="$_option_list -SPLIT"])
AS_IF([test "x$ipv6" = "xyes"],      [_option_list="$_option_list +IPV6"],    [_option_list="$_option_list -IPV6"])
AS_IF([test "x$mpls" = "xyes"],      [_option_list="$_option_list +MPLS"],    [_option_list="$_option_list -MPLS"])
_option_output=""
AS_IF([test "x$output_txt" = "xyes"],  [_option_output="${_option_output}T"])
AS_IF([test "x$output_csv" = "xyes"],  [_option_output="${_option_output}C"])
AS_IF([test "x$output_json" = "xyes"], [_option_output="${_option_output}J"])
AS_IF([test "x$output_raw" = "xyes"],  [_option_output="${_option_output}R"])
AS_IF([test "x$output_xml" = "xyes"],  [_option_output="${_option_output}X"])
AS_IF([test "x$_option_output" = "x"], [_option_list="$_option_list -OUTFMT"], [_option_list="$_option_list OUTFMT=$_option_output"])
_option_syslog=""
AS_IF([test "x$syslog_poll" = "xyes"],   [_option_syslog="${_option_syslog}P"])
AS_IF([test "x$syslog_net" = "xyes"],    [_option_syslog="${_option_syslog}N"])
AS_IF([test "x$syslog_dns" = "xyes"],    [_option_syslog="${_option_syslog}D"])
AS_IF([test "x$syslog_ipinfo" = "xyes"], [_option_syslog="${_option_syslog}I"])
AS_IF([test "x$_option_syslog" = "x"], [_option_list="$_option_list -DEBLOG"], [_option_list="$_option_list DEBLOG=$_option_syslog"])
AC_DEFINE_UNQUOTED([BUILD_OPTIONS], ["$(echo $_option_list)"], [Build options])

AC_CONFIG_HEADERS([config.h])
AH_TOP([
#ifndef CONFIG_H
#define CONFIG_H
])
AH_BOTTOM([
#endif
])

AC_CONFIG_FILES([Makefile])

# fix mandir
AS_CASE([$host_os], [freebsd*|openbsd*], [fixmandir=/usr/local], [netbsd*], [fixmandir=/usr/pkg])
AS_IF([test "x$fixmandir" != "x"], [
	AS_IF([test "x$prefix" = "xNONE"], [chkprefix=${ac_default_prefix}], [chkprefix=${prefix}])
	AS_CASE([$chkprefix], [$fixmandir], [
		AC_SUBST([mandir], [${chkprefix}/man])
		AC_MSG_NOTICE([mandir fix: $mandir])
	])
])

AC_OUTPUT

