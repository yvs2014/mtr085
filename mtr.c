/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* Mac/Solaris extensions */
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
#endif

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef LIBCAP
#include <sys/capability.h>
#endif

#if defined(LOG_TUI) || defined(LOG_POLL) || defined(LOG_NET) || defined(LOG_DNS) || defined(LOG_IPINFO)
#define WITH_SYSLOG 1
#include <syslog.h>
#endif

#ifndef AI_IDN
#  ifdef LIBIDN2
#    ifdef HAVE_IDN2_IDN2_H
#      include <idn2/idn2.h>
#    else
#      include <idn2.h>
#    endif
#    define IDN_TO_ASCII_LZ idn2_to_ascii_lz
#    define IDN_TO_ASCII_8Z idn2_to_ascii_8z
#    define IDN_STRERROR    idn2_strerror
#  elif defined(LIBIDN)
#    include <idna.h>
#    define IDN_TO_ASCII_LZ idna_to_ascii_lz
#    define IDN_TO_ASCII_8Z idna_to_ascii_8z
#    define IDN_STRERROR    idna_strerror
#  endif
#endif

#ifdef WITH_UNICODE
#  ifdef HAVE_WCTYPE_H
#    include <wctype.h>
#  endif
#  ifdef HAVE_LOCALE_H
#    include <locale.h>
#  endif
#  ifdef HAVE_LANGINFO_H
#    include <langinfo.h>
#  endif
#endif

#include "common.h"
#ifdef OUTPUT_FORMAT
#  include <ctype.h>
#endif

#include "nls.h"
#ifdef TUIMODE
#  include "tui.h"
#  include "chart.h"
#endif

#ifdef ENABLE_QOS
#if   !defined(ENABLE_QOS4)
#define VALID_QOS_AF(what, qos) do { \
  if ((af == AF_INET) && qos) {      \
    qos = 0;                         \
    errno = EOPNOTSUPP;              \
    WARNT("%s: IPv4 QOS", what);     \
  }                                  \
} while (0)
#elif !defined(ENABLE_QOS6)
#define VALID_QOS_AF(what, qos) do { \
  if ((af == AF_INET6) && qos) {     \
    qos = 0;                         \
    errno = EOPNOTSUPP;              \
    WARNT("%s: IPv6 QOS", what);     \
  }                                  \
} while (0)
#else
#define VALID_QOS_AF(what, qos) NOOP
#endif
#endif

enum OPTIONS {
#ifdef TUIMODE
  OPT_OLDLOOK  = '0',
  OPT_NEWLOOK  = '1',
//OPT_REVLOOK  = '2',
#endif
#ifdef ENABLE_IPV6
  OPT_IPV4     = '4',
  OPT_IPV6     = '6',
#endif
  OPT_ADDR     = 'a',
#ifdef ENABLE_DNS
  OPT_BOTH     = 'b',
#endif
  OPT_BITS     = 'B',
  OPT_COUNT    = 'c',
#ifdef USE_COLOR
  OPT_NOCOLOR  = 'C',
#endif
#ifdef TUIMODE
  OPT_DISPLAY  = 'd',
#endif
#ifdef WITH_MPLS
  OPT_MPLS     = 'e',
#endif
  OPT_TTLFIRST = 'f',
  OPT_FIELDS   = 'F',
  OPT_HELP     = 'h',
  OPT_INTERVAL = 'i',
#ifdef WITH_IPINFO
  OPT_LOOKUP   = 'l',
  OPT_IPINFO   = 'L',
#endif
  OPT_TTLMAX   = 'm',
#ifdef WITH_MOUSE
  OPT_MOUSE    = 'M',
#endif
#ifdef ENABLE_DNS
  OPT_NODNS    = 'n',
  OPT_NS       = 'N',
#endif
#ifdef OUTPUT_FORMAT
  OPT_OUTPUT   = 'o',
#endif
#ifdef ENABLE_QOS
  OPT_QOS      = 'q',
#endif
  OPT_REPORT   = 'r',
  OPT_SIZE     = 's',
  OPT_SUMMARY  = 'S',
  OPT_TCP      = 't',
  OPT_TIMEOUT  = 'T',
  OPT_UDP      = 'u',
  OPT_VERSION  = 'v',
  OPT_CACHE    = 'x',
#ifdef WITH_IPINFO
  OPT_MULTI_II = 'y',
#endif
};

enum TTL_OPTS {
  AUTOTTL = 'a',
};

#ifdef OUTPUT_FORMAT
typedef enum {
  OUNKN = -1,
#ifdef OUTPUT_FORMAT_TXT
  OTXT  = 't',
#endif
#ifdef OUTPUT_FORMAT_CSV
  OCSV  = 'c',
#endif
#ifdef OUTPUT_FORMAT_JSON
  OJSON = 'j',
#endif
#ifdef OUTPUT_FORMAT_TOON
  OTOON = 'n',
#endif
#ifdef OUTPUT_FORMAT_XML
  OXML  = 'x',
#endif
} oopt_type;
static oopt_type oarg = OUNKN;
#endif

#include "aux.h"
#include "net.h"
#include "display.h"

#ifdef ENABLE_DNS
#include "dns.h"
#endif

#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

enum { REPORT_PINGS = 100, TCPSYN_TOUT_MAX = 60 };

//// global vars
const char *mtrname;
static char *mtrname_dup;
int mtrtype = IPPROTO_ICMP; // ICMP as default packet type
pid_t mypid;
#ifdef OUTPUT_FORMAT
uint mtr_optc;
const char* mtr_optv[32];   // option list
#endif
char mtr_options[64];       // options in one line
#ifdef TUIMODE
tuilook_t tuilook = UNKNLOOK;
#endif
int istty; // fd=stdout
#ifdef USE_COLOR
bool nocolor;
#endif

opt_sum_t opt_sum;  // checksum options' changes

opts_t run_opts;    // runtime options
opts_t ini_opts = { // initial bool options
  .interactive = true,
#ifdef ENABLE_DNS
  .dns      = true,           // dns is on by default
#endif
  .minttl   =  1,             // start at first hop
  .maxttl   = 30,             // supposedly enough for today's internet
  .cycles   = REPORT_PINGS,   // note that 0 should be set explicitly
  .interval =  1,             // in seconds
  .size     = PAYLOAD_SIZE,   // 64 ip payload - 8 byte header
  .syn      = MIL,            // in ms (tcp timeout)
  .port     = -1,             // port from 'target:port' in tcp/udp mode
};

#ifdef ENABLE_IPV6
static bool af_specified;     // set with -4/-6 options
#endif
int sum_sock[2];              // socket summary: open()/close() calls

//
#ifdef WITH_UNICODE
bool utf_compat;
#endif
//
t_stat stats[] = {
  {.name = "",      .min = 1, .key = UNDERSCORE, .hint = _GAP_HINT},
  {.name = _LOSS_STR,  .min = 6, .key = 'L', .hint = _LOSS_HINT},
  {.name = _DROP_STR,  .min = 5, .key = 'D', .hint = _DROP_HINT},
  {.name = _RECV_STR,  .min = 6, .key = 'R', .hint = _RECV_HINT},
  {.name = _SENT_STR,  .min = 6, .key = 'S', .hint = _SENT_HINT},
  {.name = _LAST_STR,  .min = 6, .key = 'N', .hint = _LAST_HINT},
  {.name = _BEST_STR,  .min = 6, .key = 'B', .hint = _BEST_HINT},
  {.name = _AVRG_STR,  .min = 6, .key = 'A', .hint = _AVRG_HINT},
  {.name = _WRST_STR,  .min = 6, .key = 'W', .hint = _WRST_HINT},
  {.name = _STDEV_STR, .min = 6, .key = 'V', .hint = _STDEV_HINT},
  {.name = _GAVR_STR,  .min = 6, .key = 'G', .hint = _GAVR_HINT},
  {.name = _JTTR_STR,  .min = 5, .key = 'J', .hint = _JTTR_HINT},
  {.name = _JAVG_STR,  .min = 5, .key = 'M', .hint = _JAVG_HINT},
  {.name = _JMAX_STR,  .min = 5, .key = 'X', .hint = _JMAX_HINT},
  {.name = _JINT_STR,  .min = 5, .key = 'I', .hint = _JINT_HINT},
};
const int stat_max = ARRAY_LEN(stats);
//// end-of-global

static struct option long_options[] = {
  // Long, HasArgs, Flag, Short
#ifdef TUIMODE
  {"old-look",   0, 0, OPT_OLDLOOK},
  {"new-look",   0, 0, OPT_NEWLOOK},
//{"rev-look",   0, 0, OPT_REVLOOK}, // TODO: newlook with reversed title-status colors
#endif
#ifdef ENABLE_IPV6
  {"inet",       0, 0, OPT_IPV4},     // use IPv4
  {"inet6",      0, 0, OPT_IPV6},     // use IPv6
#endif
  {"address",    1, 0, OPT_ADDR},
#ifdef ENABLE_DNS
  {"show-both",  0, 0, OPT_BOTH},
#endif
  {"bitpattern", 1, 0, OPT_BITS},     // in range 0-255, or -1 for random
  {"cycles",     1, 0, OPT_COUNT},
#ifdef USE_COLOR
  {"no-color",   0, 0, OPT_NOCOLOR},  // suppress addition of color
#endif
#ifdef TUIMODE
  {"display",    1, 0, OPT_DISPLAY},
#endif
#ifdef WITH_MPLS
  {"mpls",       0, 0, OPT_MPLS},
#endif
  {"first-ttl",  1, 0, OPT_TTLFIRST}, // borrowed from traceroute
  {"fields",     1, 0, OPT_FIELDS},   // fields to display and their order
  {"help",       0, 0, OPT_HELP},
  {"interval",   1, 0, OPT_INTERVAL},
#ifdef WITH_IPINFO
  {"lookup",     0, 0, OPT_LOOKUP},
  {"ipinfo",     1, 0, OPT_IPINFO},
#endif
  {"max-ttl",    1, 0, OPT_TTLMAX},   // borrowed from traceroute
#ifdef WITH_MOUSE
  {"mouse",      0, 0, OPT_MOUSE},
#endif
#ifdef ENABLE_DNS
  {"no-dns",     0, 0, OPT_NODNS},
  {"ns",         1, 0, OPT_NS},
#endif
#ifdef OUTPUT_FORMAT
  {"output",     1, 0, OPT_OUTPUT},   // raw, txt, csv, json, toon, xml
#endif
#ifdef ENABLE_QOS
  {"tos",        1, 0, OPT_QOS},      // type-of-service (0..255)
                                      // quality-of-service
#endif
  {"report",     0, 0, OPT_REPORT},
  {"psize",      1, 0, OPT_SIZE},     // payload size
  {"summary",    0, 0, OPT_SUMMARY},  // print send/recv summary at exit
  {"tcp",        0, 0, OPT_TCP},      // TCP (note: default is ICMP)
  {"timeout",    1, 0, OPT_TIMEOUT},  // timeout for TCP sockets
  {"udp",        0, 0, OPT_UDP},      // UDP (note: default is ICMP)
  {"version",    0, 0, OPT_VERSION},
  {"cache",      1, 0, OPT_CACHE},    // enable cache with timeout in seconds
                                      // (0 means default 60sec)
#ifdef WITH_IPINFO
  {"multi",      0, 0, OPT_MULTI_II}, // show ipinfo-records for all sources
                                      // otherwise it's marked with '*' character
#endif
  { 0, 0, 0, 0 }
};
static char *short_options;

char srchost[NAMELEN];
const char *dsthost;
display_mode_t display_mode = DisplayAuto;
//

static const char *iface_addr;
//

static void setbasename(const char *argv0) {
#if   defined(HAVE_GETPROGNAME) /*BSD*/
  mtrname = getprogname();
#elif defined(HAVE_PROGRAM_INVOCATION_SHORT_NAME) /*Linux*/
  mtrname = program_invocation_short_name;
#endif
  if (!mtrname) {
    mtrname_dup = strdup(argv0);
    if (mtrname_dup)
      mtrname = basename(mtrname_dup);
    if (!mtrname)
      mtrname = argv0;
  }
}

static int my_getopt_long(int argc, char *argv[]) {
  if (!short_options) {
    short_options = calloc(ARRAY_LEN(long_options) * 2 + 1, 1);
    if (!short_options)
      return -1;
    char *ptr = short_options;
    for (int i = 0; long_options[i].name; i++) {
      *ptr++ = (char)long_options[i].val;
      if (long_options[i].has_arg)
        *ptr++ = ':';
    }
  }
  return getopt_long(argc, argv, short_options, long_options, NULL);
}

#ifdef OUTPUT_FORMAT
#define ADD_OCHAR(ch) do {        \
  if (len < (sizeof(oopt)) - 1) { \
    if (len)                      \
      oopt[len++] = VSLASH;       \
    oopt[len++] = (ch);           \
  }                               \
} while (0)
#endif

static void set_opt_desc(char opt, uint len, const char* desc[len]) NONNULL(3);
static void set_opt_desc(char opt, uint len, const char* desc[len]) {
  if (len < 1)
    return;
  const char *str = NULL, *ext = NULL;
  switch (opt) {
    case OPT_TTLFIRST:
    case OPT_TTLMAX:
#ifdef ENABLE_QOS
    case OPT_QOS:
#endif
    case OPT_BITS:    str = CAP_NUMBER;  break;
    case OPT_INTERVAL:
    case OPT_CACHE:
    case OPT_TIMEOUT: str = CAP_SECONDS; break;
    case OPT_ADDR:    str = CAP_IPADDR;  break;
    case OPT_COUNT:   str = CAP_COUNT;   break;
#ifdef TUIMODE
    case OPT_DISPLAY: str = CAP_MODE;    break;
#endif
    case OPT_SIZE:    str = CAP_BYTES;   break;
    case OPT_FIELDS:  str = CAP_FIELDS;  break;
#ifdef WITH_IPINFO
    case OPT_IPINFO:  str = CAP_SERVER; ext = CAP_FIELDS; break;
#endif
#ifdef ENABLE_DNS
    case OPT_NS:      str = CAP_IPADDR;  break;
#endif
#ifdef OUTPUT_FORMAT
    case OPT_OUTPUT: {
      static char oopt[16];
      uint len = 0;
#ifdef OUTPUT_FORMAT_TXT
      ADD_OCHAR(OTXT);
#endif
#ifdef OUTPUT_FORMAT_CSV
      ADD_OCHAR(OCSV);
#endif
#ifdef OUTPUT_FORMAT_JSON
      ADD_OCHAR(OJSON);
#endif
#ifdef OUTPUT_FORMAT_TOON
      ADD_OCHAR(OTOON);
#endif
#ifdef OUTPUT_FORMAT_XML
      ADD_OCHAR(OXML);
#endif
      str = oopt;
    } break;
#endif
    default: break;
  }
  desc[0] = str;
  if (len > 1)
    desc[1] = ext;
}

NORETURN static void usage(int status) {
  const char *rest = TTY_NORM;
  const char *bold = TTY_BOLD;
  const char *yell = TTY_YELLOW;
  printf("%s: %s%s%s [", STR_USAGE, bold, mtrname, rest);
  uint len = strlen(short_options);
  printf("%s-", yell);
  for (uint i = 0; i < len; i++)
    if (short_options[i] != ':')
      putchar(short_options[i]);
  printf("%s", rest);
  printf("] %s%s%s[:%s] ...\n", bold, CAP_TARGET, rest, CAP_PORT);
  for (int i = 0; long_options[i].name; i++) {
    printf("\t[%s", yell);
    char opt = (char)long_options[i].val;
    if (opt) {
      printf("-%c%s|%s", opt, rest, yell);
    }
    printf("--%s%s", long_options[i].name, rest);
    if (long_options[i].has_arg) {
      const char *desc[2] = {0};
      set_opt_desc(opt, ARRAY_LEN(desc), desc);
      if (desc[0])
        printf(" %s", desc[0]);
      if (desc[1])
        printf(",%s", desc[1]);
    }
    printf("]\n");
  }
  exit(status);
}

#ifdef ENABLE_DNS
static bool set_custom_res(struct addrinfo *ns) {
  if (ns && ns->ai_addr && (
#ifdef ENABLE_IPV6
       (ns->ai_family == AF_INET6) ? addr6exist(&((struct sockaddr_in6 *)ns->ai_addr)->sin6_addr) :
#endif
      ((ns->ai_family == AF_INET)  ? addr4exist(&((struct sockaddr_in *)ns->ai_addr)->sin_addr) : false))) {
    if (custom_res) {
      free(custom_res);
      WARNXT("%s", MANYNS_WARN);
    }
    custom_res = malloc(sizeof(*custom_res));
    if (custom_res) {
      memcpy(custom_res, ns->ai_addr, ns->ai_addrlen);
      uint16_t *port =
#ifdef ENABLE_IPV6
        (ns->ai_family == AF_INET6) ? &custom_res->S6PORT :
#endif
       ((ns->ai_family == AF_INET)  ? &custom_res->S_PORT : NULL);
      if (port && !*port) *port = htons(53);
      return true;
    }
  }
  return false;
}
#endif

#ifdef ENABLE_IPV6
static const char* two_colons(const char *s) {
  if (s) { s = strchr(s, ':'); if (s) s++; }
  return s ? strchr(s, ':') : NULL;
}
#endif

static bool split_hostport(char *buff, char* hostport[2]) NONNULL(1, 2);
static bool split_hostport(char *buff, char* hostport[2]) {
   char *host = trim(buff), *port = NULL;
   if (!host)
     return false;
#ifdef ENABLE_IPV6
   if (host[0] == '[') {
     port = strrchr(host, ']');
     if (!port) return false;
     *port++ = 0; port = trim(port);
     if (port && (port[0] == ':')) port++;
     port = trim(port);
     host++; host = trim(host);
   } else if (!two_colons(host))
#endif
   { port = strrchr(host, ':');
     if (port) { *port++ = 0; port = trim(port); host = trim(host); }}
   hostport[0] = (host && host[0]) ? host : NULL;
   hostport[1] = (port && port[0]) ? port : NULL;
   return true;
}

#ifdef TUIMODE
#define VAL_TRU(nth) ((val & (1u << ((nth) - 1))) ? true : false)
static void option_display(char opt, const char *arg) NONNULL(2);
static void option_display(char opt, const char *arg) {
  int val = arg2int(opt, arg, 0, INT8_MAX, DISPMODE_ERR, NULL, 0);
  chart_mode = (val & ~8) % chart_mode_max;
  ini_opts.chart   = val & 3;    // first two bits
                                 // 3rd reserved
  ini_opts.color   = VAL_TRU(4); // 4th
  ini_opts.audible = VAL_TRU(5); // 5th
  ini_opts.visible = VAL_TRU(6); // 6th
  ini_opts.bell    = VAL_TRU(7); // 7th
}
#undef VAL_TRU
#endif

static void option_fields(char opt, const char *arg) NONNULL(2);
static void option_fields(char opt, const char *arg) {
  if (strnlen(arg, MAXFLD + 1) > MAXFLD)
    ERRXT(EINVAL, "-%c: %s (%s=%d): %s", opt, OVERFLD_ERR, MAX_STR, MAXFLD, arg);
  for (const char *c = arg; c && *c; c++) {
    uint cnt = 0;
    for (; cnt < ARRAY_LEN(stats); cnt++)
      if (*c == stats[cnt].key)
        break;
    if (cnt >= ARRAY_LEN(stats))
      ERRXT(EINVAL, "-%c: %s: %c", opt, UNKNFLD_ERR, *c);
  }
  set_fld_active(arg);
}

#ifdef ENABLE_DNS
static void option_ns(char opt, const char *arg) NONNULL(2);
static void option_ns(char opt, const char *arg) {
  char buff[MAX_ADDRSTRLEN + 6/*:port*/] = {0};
  snprinte(buff, sizeof(buff), "%s", arg);
  if (!buff[0])
    ERRT(EINVAL, "-%c", opt);
  char* hostport[2] = {0};
  if (!split_hostport(buff, hostport))
    ERRXT(EINVAL, "-%c: %s: %.*s", opt, PARSE_ERR, sizeof(buff), buff);
  if (!hostport[1])
    hostport[1] = "53";
  struct addrinfo *ns = NULL, hints = {
    .ai_family   = AF_UNSPEC,
    .ai_socktype = SOCK_DGRAM,
    .ai_flags    = AI_NUMERICHOST | AI_NUMERICSERV };
  int rc = getaddrinfo(hostport[0], hostport[1], &hints, &ns);
  if (rc || !ns) {
    if (rc == EAI_SYSTEM)
      ERRT(errno, "%s", "getaddrinfo()");
    ERRXT(EINVAL, "-%c: %s: %s", opt, gai_strerror(rc), arg);
  }
  if (!set_custom_res(ns))
    ERRXT(EXIT_FAILURE, "-%c: %s %s", opt, SETNS_ERR, arg);
  freeaddrinfo(ns);
}
#endif

#ifdef OUTPUT_FORMAT
static inline void option_output(const char *arg) NONNULL(1);
static inline void option_output(const char *arg) {
  char opt = tolower((int)arg[0]);
  display_mode_t was = display_mode;
  switch (opt) {
#ifdef OUTPUT_FORMAT_TXT
    case OTXT:  display_mode = DisplayTXT;  break;
#endif
#ifdef OUTPUT_FORMAT_CSV
    case OCSV:  display_mode = DisplayCSV;  break;
#endif
#ifdef OUTPUT_FORMAT_JSON
    case OJSON: display_mode = DisplayJSON; break;
#endif
#ifdef OUTPUT_FORMAT_TOON
    case OTOON: display_mode = DisplayTOON; break;
#endif
#ifdef OUTPUT_FORMAT_XML
    case OXML:  display_mode = DisplayXML;  break;
#endif
    default: usage(EXIT_FAILURE);
  }
  if ((oarg != OUNKN) && (oarg != opt))
    ERRXT(EINVAL, "-%c%c -%c%c: %s", OPT_OUTPUT, oarg, OPT_OUTPUT, opt, MUTEXCL_ERR);
  if (was == DisplayReport)
    ERRXT(EINVAL,   "-%c -%c%c: %s", OPT_REPORT,       OPT_OUTPUT, opt, MUTEXCL_ERR);
  oarg = (uint8_t)opt;
  if (ini_opts.cycles <= 0)
    ini_opts.cycles = REPORT_PINGS;
}
#endif

NORETURN static inline void option_version(uint count UNUSED) {
#ifdef BUILD_OPTIONS
  printf("%s%s.%s%s: %s\n", TTY_BOLD, PACKAGE_NAME, GITREV, TTY_NORM, BUILD_OPTIONS);
#else
  printf("%s.%s\n", PACKAGE_NAME, GITREV);
#endif
#ifdef TUIMODE
  if (count > 1)
    printf("%s%s%s: %s\n", TTY_BOLD, "TUI", TTY_NORM, tui_version());
#endif
  exit(EXIT_SUCCESS);
}

static inline void ineractive_modes(display_mode_t mode) {
  switch (mode) {
    case DisplayReport:
#ifdef OUTPUT_FORMAT_TXT
    case DisplayTXT:
#endif
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV:
#endif
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON:
#endif
#ifdef OUTPUT_FORMAT_TOON
    case DisplayTOON:
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
      run_opts.interactive = false;
      break;
    default: break;
  }
}

#ifdef OUTPUT_FORMAT
static void set_optv(int argc, char **argv) {
  mtr_optc = 0;
  for (int i = 1; (i < argc) && (mtr_optc < ARRAY_LEN(mtr_optv)); i++)
    if (argv[i])
      mtr_optv[mtr_optc++] = argv[i];
}
#endif

static void short_set(char opt) {
  switch (opt) {
#ifdef TUIMODE
    case OPT_OLDLOOK:
    case OPT_NEWLOOK: {
      bool nownew = (opt == OPT_NEWLOOK);
      bool wasnew = (tuilook == NEWLOOK);
      bool wasold = (tuilook == OLDLOOK);
      if ((wasold && nownew) || (wasnew && !nownew))
        ERRXT(EINVAL, "-%c -%c: %s", wasnew ? OPT_NEWLOOK : OPT_OLDLOOK, opt, MUTEXCL_ERR);
      tuilook = nownew ? NEWLOOK : OLDLOOK;
#ifdef WITH_MOUSE
      ini_opts.mouse = nownew;
#endif
    } break;
#endif
#ifdef ENABLE_IPV6
    case OPT_IPV4:
    case OPT_IPV6: {
      bool nowip4 = (opt == OPT_IPV4);
      bool wasip4 = (af == AF_INET);
      bool wasip6 = (af == AF_INET6);
      if (af_specified && ((wasip6 && nowip4) || (wasip4 && !nowip4)))
        ERRXT(EINVAL, "-%c -%c: %s", wasip4 ? OPT_IPV4 : OPT_IPV6, opt, MUTEXCL_ERR);
      net_settings(nowip4 ? IPV6_DISABLED : IPV6_ENABLED);
      af_specified = true;
    } break;
#endif
    case OPT_ADDR:
      if (optarg)
        iface_addr = optarg;
      break;
#ifdef ENABLE_DNS
    case OPT_BOTH:
      ini_opts.both = true;
      break;
#endif
    case OPT_BITS:
      if (optarg)
        ini_opts.pattern = arg2int(opt, optarg, -1, UINT8_MAX, BITPATT_STR, NULL, 0);
      break;
    case OPT_COUNT:
      if (optarg)
        ini_opts.cycles = arg2int(opt, optarg, -1, INT_MAX, NCYCLES_STR, NULL, 0);
      break;
#ifdef USE_COLOR
    case OPT_NOCOLOR:
      nocolor = true;
      break;
#endif
#ifdef TUIMODE
    case OPT_DISPLAY:
      if (optarg)
        option_display(opt, optarg);
      break;
#endif
#ifdef WITH_MPLS
    case OPT_MPLS:
      ini_opts.mpls = true;
      break;
#endif
    case OPT_TTLFIRST: if (optarg) {
      if ((optarg[0] == AUTOTTL) && !optarg[1])
        ini_opts.endpoint = true;
      else
        ini_opts.minttl = arg2int(opt, optarg, 1, ini_opts.maxttl, MINTTL_STR, NULL, 0);
    } break;
    case OPT_FIELDS:
      if (optarg)
        option_fields(opt, optarg);
      break;
    case OPT_INTERVAL:
      if (optarg)
        ini_opts.interval = arg2int(opt, optarg, 1, INT_MAX, INTERVAL_STR, NULL, 0);
      break;
    case OPT_TTLMAX:
      if (optarg)
        ini_opts.maxttl = arg2int(opt, optarg, ini_opts.minttl, MAXHOST, MAXTTL_STR, NULL, 0);
      break;
#ifdef WITH_MOUSE
    case OPT_MOUSE:
      ini_opts.mouse = false;
      break;
#endif
#ifdef ENABLE_DNS
    case OPT_NODNS:
      ini_opts.dns = false;
      break;
    case OPT_NS:
      if (optarg)
        option_ns(opt, optarg);
      break;
#endif
#ifdef OUTPUT_FORMAT
    case OPT_OUTPUT:
      if (optarg)
        option_output(optarg);
      break;
#endif
#ifdef ENABLE_QOS
    case OPT_QOS: if (optarg) {
      ini_opts.qos = arg2int(opt, optarg, 0, UINT8_MAX, QOSTOS_STR, NULL, 0);
      VALID_QOS_AF(QOSTOS_STR, ini_opts.qos);
    } break;
#endif
    case OPT_REPORT:
#ifdef OUTPUT_FORMAT
      if (oarg != OUNKN)
        ERRXT(EINVAL, "-%c%c -%c: %s", OPT_OUTPUT, oarg, opt, MUTEXCL_ERR);
#endif
      display_mode = DisplayReport;
      if (ini_opts.cycles <= 0)
        ini_opts.cycles = REPORT_PINGS;
      break;
    case OPT_SIZE: if (optarg) {
      int max = MAXPACKET - MINPACKET;
      ini_opts.size = arg2int(opt, optarg, -max, max, PSIZE_STR, NULL, 0);
    } break;
    case OPT_SUMMARY:
      ini_opts.stat = true;
      break;
    case OPT_TIMEOUT:
      if (optarg)
        ini_opts.syn = arg2int(opt, optarg, 1, TCPSYN_TOUT_MAX, TCPTM_STR, NULL, 0) * MIL;
      break;
    case OPT_TCP:
    case OPT_UDP: {
      bool udp = (opt == OPT_UDP);
      if ((udp && ini_opts.tcp) || (!udp && ini_opts.udp))
        ERRXT(EINVAL, "-%c -%c: %s", ini_opts.udp ? OPT_UDP: OPT_TCP, opt, MUTEXCL_ERR);
      net_set_type(IPPROTO_TCP);
      if (udp)
        ini_opts.udp = true;
      else
        ini_opts.tcp = true;
    } break;
    case OPT_VERSION:
      break;
    case OPT_CACHE:
      if (optarg)
        ini_opts.cache = arg2int(opt, optarg, 0, INT_MAX, CACHETM_STR, NULL, 0);
      break;
#ifdef WITH_IPINFO
    case OPT_LOOKUP:
    case OPT_IPINFO: {
      const char *arg = (opt == OPT_IPINFO) ? optarg : NULL;
      if (arg)
        ini_opts.ipinfo = true;
      else
        ini_opts.asn    = true;
      if (!ipinfo_init(arg))
        exit(EXIT_FAILURE);
      if (!ipinfo_action(ActionNone)) // fail to init
        exit(EXIT_FAILURE);
    } break;
    case OPT_MULTI_II:
      ini_opts.multi = true;
      break;
#endif
    default:
      usage((opt == OPT_HELP) ? EXIT_SUCCESS : EXIT_FAILURE);
  }
}


static void parse_options(int argc, char **argv) {
  int opt = 0;
  uint countv = 0;
  while ((opt = my_getopt_long(argc, argv)) >= 0) {
    short_set((char)opt);
    switch (opt) { // option processing with extra args
#ifdef OUTPUT_FORMAT
      case OPT_OUTPUT: if (!mtr_optc) set_optv(argc, argv); break;
#endif
      case OPT_VERSION: countv++; break;
      default: break;
    }
  }
  if (countv > 0)
    option_version(countv);
#ifdef TUIMODE
  if (tuilook == UNKNLOOK)
    tuilook = OLDLOOK; // by default so far at wip
#endif
#ifdef WITH_MOUSE
  if (ini_opts.mouse && !((display_mode == DisplayTUI) || (display_mode == DisplayAuto))) {
    WARNXT("%s", MOUSE_OUT_STR);
    ini_opts.mouse = false;
  }
#endif
#ifdef USE_COLOR
  if (ini_opts.color && nocolor) {
    WARNXT("-%c: %s", OPT_NOCOLOR, DISCOLOR_ERR);
    ini_opts.color = false;
  }
#endif
  run_opts = ini_opts; // to reflect possible interactive changes
  for (int i = 1, len = 0; (i < optind) && (i < argc) && argv[i] && ((uint)len < sizeof(mtr_options)); i++) {
    int inc = snprinte(mtr_options + len, sizeof(mtr_options) - len, (i > 1) ? " %s" : "%s", argv[i]);
    if (inc < 0)
      break;
    len += inc;
  }
  ineractive_modes(display_mode);
}

static inline const struct addrinfo* find_ai_af(const struct addrinfo *res) {
  const struct addrinfo *ai = NULL;
  for (ai = res; ai; ai = ai->ai_next)
    if (ai->ai_family == af) // desired AF
      break;
  if (ai && (ai->ai_family != af)) ai = NULL; // unsuitable AF
  if (!ai) // not found
#ifdef ENABLE_IPV6
    WARNXT("%s: %s: IPv%c: %s", TARGET_STR, dsthost,
      af == AF_INET ? OPT_IPV4 : OPT_IPV6, NOADDR_ERR);
#else
    WARNXT("%s: %s: %s", TARGET_STR, dsthost, NOADDR_ERR);
#endif
  return ai;
}

#ifdef ENABLE_IPV6
static inline const struct addrinfo* find_ai_pref(const struct addrinfo *res) {
  // preference: first ipv4, second ipv6
  const struct addrinfo *ai = NULL;
  for (ai = res; ai; ai = ai->ai_next) if (ai->ai_family == AF_INET) break;
  if (!ai)
    for (ai = res; ai; ai = ai->ai_next) if (ai->ai_family == AF_INET6) break;
  if (!ai)
    WARNXT("%s: %s: %s", TARGET_STR, dsthost, strerror(EADDRNOTAVAIL));
  else if (af != ai->ai_family) {
    af = ai->ai_family;
    net_settings((af == AF_INET6) ? IPV6_ENABLED : IPV6_DISABLED);
  }
  return ai;
}
#endif

// return: failed or not
static int set_target(const struct addrinfo *res) {
  int rc = -1;
  const struct addrinfo *ai =
#ifdef ENABLE_IPV6
    !af_specified ? find_ai_pref(res) :
#endif
    find_ai_af(res);
  if (ai) {
    t_ipaddr *host =
#ifdef ENABLE_IPV6
      (af == AF_INET6) ? (t_ipaddr*)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr :
#endif
      ((af == AF_INET) ? (t_ipaddr*)&((struct sockaddr_in  *)ai->ai_addr)->sin_addr  : NULL);
    if (af && host && net_set_host(host)) {
      if (iface_addr && !net_set_ifaddr(iface_addr))
        WARNXT("%s: %s", USEADDR_ERR, iface_addr);
      else
        rc = 0; // success
    } else
      WARNXT("%s (af=%d)", HOSTENT_ERR, af);
  }
  return rc;
}

#if defined(WITH_UNICODE) && defined(USE_NLS)
static void bind_nls(void) {
#ifdef HAVE_LOCALE_H
  setlocale(LC_ALL, "");
#endif
#ifdef LOCALEDIR
  bindtextdomain(PACKAGE_NAME, LOCALEDIR);
  textdomain(PACKAGE_NAME);
#endif
}
#define BIND_NLS bind_nls()
#else
#define BIND_NLS NOOP
#endif

#if defined(WITH_UNICODE) && defined(HAVE_LOCALE_H) && defined(HAVE_LANGINFO_H)
static void init_locale(void) {
  setlocale(LC_CTYPE, "");
  if (strcasecmp("UTF-8", nl_langinfo(CODESET)) == 0) { // NOLINT(concurrency-mt-unsafe)
    if (iswprint(L'▁')) {
#ifdef TUIMODE
      chart_mode_max++;
#endif
      utf_compat = true;
      return;
    }
    WARNXT("%s", UNOPRINT_ERR);
  }
  setlocale(LC_CTYPE, NULL);
}
#define UNICODE_INIT do { init_locale(); if (utf_compat) BIND_NLS; } while (0)
#define UNICODE_FREE setlocale(LC_CTYPE, NULL)
#else
#define UNICODE_INIT BIND_NLS
#define UNICODE_FREE NOOP
#endif /* UNICODE stuff */

#ifdef LIBCAP
static bool drop_caps(void) {
  bool okay = false;
  cap_t caps = cap_init();
  if (caps) {
    okay = (cap_set_proc(caps) == 0);
    if (!okay)
      warn("%s", "cap_set_proc()");
    cap_free(caps);
  } else
    warn("%s", "cap_init()");
  return okay;
}
#endif

typedef struct {
  const char *target, *error;
  struct addrinfo *res, hints;
  int rc;
} t_res_rc;

static void getaddrinfo_e(t_res_rc *rr, const char *name) {
  if (!rr || !name) return;
  rr->rc = getaddrinfo(name, NULL, &rr->hints, &rr->res);
  if (rr->rc) rr->error =
    (rr->rc == EAI_SYSTEM) ? rstrerror(errno) : gai_strerror(rr->rc);
#if defined(ENABLE_IPV6) && defined(IN6_IS_ADDR_V4MAPPED)
  else if (!af_specified && rr->res && (rr->res->ai_family == AF_INET6)) {
    struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)rr->res->ai_addr;
    if (sa6 && IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) { // unmap and set ipv4 address
      struct sockaddr_in sa4 = { .sin_family = AF_INET,
        .sin_addr.s_addr = ((uint32_t*)&sa6->sin6_addr)[3] };
      memcpy(sa6, &sa4, sizeof(sa4));
      rr->res->ai_addrlen = sizeof(sa4);
      rr->res->ai_family = AF_INET;
    }
  }
#endif
}

#if !defined(AI_IDN) && (defined(LIBIDN2) || defined(LIBIDN))
static void idn_resolv(t_res_rc *rr, int (*idn2ascii)(const char*, char**, int)) {
  if (rr && idn2ascii) {
    char *name = NULL;
    rr->rc = idn2ascii(rr->target, &name, 0);
    if (!rr->rc && name)
      getaddrinfo_e(rr, name);
    else
      rr->error = IDN_STRERROR(rr->rc);
    if (name)
      free(name);
  }
}
#endif

static void try_to_resolv(t_res_rc *rr) NONNULL(1);
static void try_to_resolv(t_res_rc *rr) {
  if (rr->target) {
    getaddrinfo_e(rr, rr->target);
#if !defined(AI_IDN) && (defined(LIBIDN2) || defined(LIBIDN))
    if (rr->rc) {
      idn_resolv(rr, IDN_TO_ASCII_LZ);
      if (rr->rc)
        idn_resolv(rr, IDN_TO_ASCII_8Z);
    }
#endif
  }
}

static void resolv_with_port(t_res_rc *rr) NONNULL(1);
static void resolv_with_port(t_res_rc *rr) {
  const t_res_rc copy = *rr;
  char buff[MAX_ADDRSTRLEN + 6/*:port*/] = {0};
  if (snprinte(buff, sizeof(buff), "%s", dsthost) < 0)
    return;
  char* hostport[2] = {0};
  if (split_hostport(buff, hostport)) {
    errno = 0;
    if (hostport[1]) {
      int num = arg2int(-1, hostport[1], 1, USHRT_MAX, PORTNUM_STR, NULL, 0);
      if (!errno)
        ini_opts.port = num;
    }
    if (!errno && hostport[0]) {
      *rr = copy;
      rr->target = hostport[0];
      try_to_resolv(rr);
    }
    if (errno)
      errno = 0;
  } else
    WARNXT("%s: %s", PARSE_ERR, buff);
}

static inline void stat_fin(void) {
  printf("SOCKET: %u %s, %u %s\n", sum_sock[0], OPENED_STR, sum_sock[1], CLOSED_STR);
  printf("NET: %lu %s (%lu icmp, %lu udp, %lu tcp), %lu %s (%lu icmp, %lu udp, %lu tcp)\n",
    net_queries[0], QUERIES_STR, net_queries[1], net_queries[2], net_queries[3],
    net_replies[0], REPLIES_STR, net_replies[1], net_replies[2], net_replies[3]);
#ifdef ENABLE_DNS
  printf("DNS: %u %s (%u ptr, %u txt), %u %s (%u ptr, %u txt)\n",
    dns_queries[0], QUERIES_STR, dns_queries[1], dns_queries[2],
    dns_replies[0], REPLIES_STR, dns_replies[1], dns_replies[2]);
#endif
#ifdef WITH_IPINFO
  printf("IPINFO: %u %s (%u http, %u whois), %u %s (%u http, %u whois)\n",
    ipinfo_queries[0], QUERIES_STR, ipinfo_queries[1], ipinfo_queries[2],
    ipinfo_replies[0], REPLIES_STR, ipinfo_replies[1], ipinfo_replies[2]);
#endif
}

static inline void main_prep(int argc, char **argv) {
  net_assert();
#ifdef USE_COLOR
  istty = isatty(1);
  if (!istty)
    errno = 0;
#endif
  mypid = getpid();
#ifndef HAVE_ARC4RANDOM_UNIFORM
  srand(mypid); // reset random seed
#endif
  for (uint i = 0; i < ARRAY_LEN(stats); i++)
    fld_index[(uint8_t)stats[i].key] = i;
  set_fld_active(NULL);
  parse_options(argc, argv);
  if (optind >= argc) // TODO: set target at runtime
    usage(EXIT_SUCCESS);
#ifdef WITH_SYSLOG
  openlog(PACKAGE_NAME, LOG_PID, LOG_USER);
#endif
#ifdef ENABLE_IPV6
  net_setsock6();
#endif
#ifdef ENABLE_DNS
  if (run_opts.dns)
    dns_open();
#endif
  if (gethostname(srchost, sizeof(srchost)))
    snprinte(srchost, sizeof(srchost), "%s", NONE_STR);
  display_start((argc > optind) ? (argc - optind) : 0);
}

// return: failed or not
static inline int main_loop(struct addrinfo *ai, bool fin) {
  static bool next_target;
  int rc = -1;
  if (ai) {
    rc = set_target(ai);
    if (!rc) {
#ifdef ENABLE_QOS
      VALID_QOS_AF(dsthost, run_opts.qos);
#endif
      if (display_open())
        display_loop();
      else
        WARNXT("%s", OPENDISP_ERR);
      net_end_transit();
      if (fin)
        display_confirm_fin();
      display_close(next_target);
      if (!next_target)
        next_target = true;
    }
    freeaddrinfo(ai);
  } else
    WARNXT("%s %s", RESFAIL_ERR, dsthost);
  return rc;
}

static inline void main_fin(void) {
  display_final();
#ifdef WITH_IPINFO
  ipinfo_close();
#endif
#ifdef ENABLE_DNS
  dns_close();
#endif
  net_close();
#ifdef WITH_SYSLOG
  closelog();
#endif
  if (run_opts.stat)
    stat_fin();
  if (strerr_txt[0] && (display_mode == DisplayTUI))
    WARNXT("%s", strerr_txt); // duplicate an error cleaned by ncurses
  UNICODE_FREE;
  if (mtrname_dup) {
    mtrname = "";
    free(mtrname_dup);
    mtrname_dup = NULL;
  }
}

// return: failed or not
static int resolv_n_ping(int port, bool fin) {
  tgterr_txt[0] = 0;    // clear per target error message
  ini_opts.port = port; // set initial port
  t_res_rc rr = {       // default resolv data
    .target = dsthost,
    .hints = {
#ifdef ENABLE_IPV6
      .ai_family = af_specified ? af : AF_UNSPEC,
#else
      .ai_family = AF_INET,
#endif
      .ai_socktype = SOCK_DGRAM,
#ifdef AI_IDN
      .ai_flags = AI_IDN,
#endif
    }
  };
  try_to_resolv(&rr);
  if (rr.rc && ((mtrtype == IPPROTO_TCP) || (mtrtype == IPPROTO_UDP)))
    resolv_with_port(&rr);
  if (rr.res && !rr.rc)
    rr.rc = main_loop(rr.res, fin);
  else
    WARNXT("%s %s: %s", RESFAIL_ERR, dsthost, rr.error ? rr.error : UNKNOWN_ERR);
  return rr.rc;
}

int main(int argc, char **argv) {
  // get raw sockets
  if (!net_open())
    errx(EXIT_FAILURE, "Unable to get raw sockets");
  // drop permissions if that's set
  if (setgid(getgid()) || setuid(getuid()))
    errx(EXIT_FAILURE, "Unable to drop permissions");
  // be sure
  if ((geteuid() != getuid()) || (getegid() != getgid()))
    errx(EXIT_FAILURE, "Unable to drop permissions");
#ifdef LIBCAP
  if (!drop_caps())
    errx(EXIT_FAILURE, "Unable to drop capabilities");
#endif
  setbasename(argv[0]);
#ifdef USE_COLOR
  istty = isatty(1);
  if (!istty)
    errno = 0;
#endif
  UNICODE_INIT;
  for (uint i = 0; i < ARRAY_LEN(stats); i++) {
    if (stats[i].name && stats[i].name[0]) {
      stats[i].name  = _(stats[i].name);
      stats[i].len   = ustrnlen(stats[i].name, NAMELEN);
      if (stats[i].min <= stats[i].len)
        stats[i].min = stats[i].len + 1;
    }
    if (stats[i].hint && stats[i].hint[0])
      stats[i].hint  = _(stats[i].hint);
  }
  main_prep(argc, argv);
  //
  int port = ini_opts.port;
  int ec = 0;
  for (int ndx = optind; (ndx < argc) && argv[ndx];) {
    dsthost = argv[ndx++]; // there's ++
    int rc = resolv_n_ping(port, ndx == argc);
    if (rc && !ec)
      ec = rc;
  }
  //
  main_fin();
  return strerr_txt[0] ? EXIT_FAILURE : ec;
}

