
#ifndef CONFIG_H
#define CONFIG_H

#cmakedefine PACKAGE_NAME "@PACKAGE_NAME@"
#cmakedefine VERSION "@VERSION@"
#cmakedefine GITREV "@GITREV@"
#cmakedefine BUILD_OPTIONS "@BUILD_OPTIONS@"

/* Linux capabilities */
#cmakedefine LIBCAP

/* Curses support */
#cmakedefine CURSESMODE
#cmakedefine HAVE_NCURSESW_NCURSES_H
#cmakedefine HAVE_NCURSESW_CURSES_H
#cmakedefine HAVE_NCURSES_NCURSES_H
#cmakedefine HAVE_NCURSES_CURSES_H
#cmakedefine HAVE_NCURSES_H
#cmakedefine HAVE_CURSES_H
#cmakedefine HAVE_USE_DEFAULT_COLORS

/* Unicode related */
#cmakedefine WITH_UNICODE
#cmakedefine HAVE_WCHAR_H
#cmakedefine HAVE_WCTYPE_H
#cmakedefine HAVE_LOCALE_H
#cmakedefine HAVE_LANGINFO_H

/* DNS stuff */
#cmakedefine ENABLE_DNS
#cmakedefine HAVE_RES_NMKQUERY
#cmakedefine HAVE_SYS_TYPES_H
#cmakedefine HAVE_NETDB_H
#cmakedefine HAVE_NETINET_IN_H
#cmakedefine HAVE_ARPA_NAMESER_H

/* IDN capabilities */
#cmakedefine LIBIDN
#cmakedefine LIBIDN2

/* IP-info lookup */
#cmakedefine WITH_IPINFO

/* split-mode */
#cmakedefine SPLITMODE

/* XCB/Xlib cairo graphs */
#cmakedefine GRAPHMODE
#cmakedefine WITH_XCB_GRAPHS
#cmakedefine WITH_X11_GRAPHS
#cmakedefine FC_FINI

/* IPv6 */
#cmakedefine ENABLE_IPV6

/* MPLS decoding */
#cmakedefine WITH_MPLS

/* output formats */
#cmakedefine OUTPUT_FORMAT_RAW
#cmakedefine OUTPUT_FORMAT_TXT
#cmakedefine OUTPUT_FORMAT_CSV
#cmakedefine OUTPUT_FORMAT_JSON
#cmakedefine OUTPUT_FORMAT_XML

/* debug via syslog */
#cmakedefine LOG_POLL
#cmakedefine LOG_NET
#cmakedefine LOG_DNS
#cmakedefine LOG_IPINFO


/*
 aux settings
*/

/* arc4 functions */
#cmakedefine HAVE_ARC4RANDOM_UNIFORM
#cmakedefine ARC4_IN_BSD_STDLIB_H

/* sys/param.h header */
#cmakedefine HAVE_SYS_PARAM_H


#endif

