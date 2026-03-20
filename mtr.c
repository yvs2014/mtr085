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
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "common.h"
#include "nls.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef LIBCAP
#include <sys/capability.h>
#endif

#if defined(LOG_DNS) || defined(LOG_IPINFO) || defined(LOG_NET) || defined(LOG_POLL)
#define WITH_SYSLOG 1
#include <syslog.h>
#endif

#ifndef AI_IDN
#if   defined(LIBIDN2)
#if   defined(HAVE_IDN2_IDN2_H)
#include <idn2/idn2.h>
#else
#include <idn2.h>
#endif
#define IDN_TO_ASCII_LZ idn2_to_ascii_lz
#define IDN_TO_ASCII_8Z idn2_to_ascii_8z
#define IDN_STRERROR    idn2_strerror
#elif defined(LIBIDN)
#include <idna.h>
#define IDN_TO_ASCII_LZ idna_to_ascii_lz
#define IDN_TO_ASCII_8Z idna_to_ascii_8z
#define IDN_STRERROR    idna_strerror
#endif
#endif

#ifdef WITH_UNICODE
#ifdef HAVE_WCTYPE_H
#include <wctype.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif
#endif

#if defined(OUTPUT_FORMAT_RAW) || defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_JSON) || defined(OUTPUT_FORMAT_TOON) || defined(OUTPUT_FORMAT_XML)
#define OUTPUT_FORMAT
#include <ctype.h>
#endif

enum OPTIONS {
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
#ifdef CURSESMODE
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
#ifdef ENABLE_DNS
  OPT_NODNS    = 'n',
  OPT_NS       = 'N',
#endif
#ifdef OUTPUT_FORMAT
  OPT_OUTPUT   = 'o',
#endif
#ifdef SPLITMODE
  OPT_SPLIT    = 'p',
#endif
#ifdef IP_TOS
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
};

enum TTL_OPTS {
  AUTOTTL = 'a',
};

#ifdef OUTPUT_FORMAT
enum OUTPUT_OPTS {
#ifdef OUTPUT_FORMAT_RAW
  ORAW  = 'r',
#endif
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
};
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
#ifdef OUTPUT_FORMAT_RAW
#include "report.h"
#endif

#ifdef HAVE_QUICK_EXIT
#define QEXIT quick_exit
#else
#define QEXIT exit
#endif

enum { REPORT_PINGS = 100, CACHE_TIMEOUT = 60, TCPSYN_TOUT_MAX = 60 };

//// global vars
int mtrtype = IPPROTO_ICMP;   // ICMP as default packet type
pid_t mypid;
char mtr_args[128];           // args to display in curses title
#if defined(OUTPUT_FORMAT_JSON) || defined(OUTPUT_FORMAT_TOON)
#define OUTPUT_OPTV
#endif
#ifdef OUTPUT_OPTV
const char* mtr_optv[32];     // option string array
uint mtr_optc;
#endif

opt_sum_t opt_sum;  // checksum options' changes

opts_t run_opts;    // runtime options
opts_t ini_opts = { // initial bool options
  .interactive = true,
  .dns      = true,           // dns is on by default
  .minttl   =  1,             // start at first hop
  .maxttl   = 30,             // supposedly enough for today's internet
  .cycles   = REPORT_PINGS,   // note that 0 should be set explicitly
  .interval =  1,             // in seconds
  .size     = PAYLOAD_SIZE,   // 64 ip payload - 8 byte header
  .syn      = MIL,            // in ms (tcp timeout)
  .cache    = CACHE_TIMEOUT,  // in seconds (cache timeout)
  .port     = -1,             // port from 'target:port' in tcp/udp mode
};

#ifdef ENABLE_IPV6
static bool af_specified;     // set with -4/-6 options
#endif
int sum_sock[2];              // socket summary: open()/close() calls
// chart related
int display_offset;
int curses_mode;              // 1st and 2nd bits, 3rd is reserved
#ifdef CURSESMODE
int curses_mode_max = 3;
#endif
//
t_stat stats[] = {
  {.name = "",      .min = 1, .key = BLANK_INDICATOR, .hint = _GAP_HINT},
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
#ifdef CURSESMODE
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
#ifdef ENABLE_DNS
  {"no-dns",     0, 0, OPT_NODNS},
  {"ns",         1, 0, OPT_NS},
#endif
#ifdef OUTPUT_FORMAT
  {"output",     1, 0, OPT_OUTPUT},   // raw, txt, csv, json, toon, xml
#endif
#ifdef SPLITMODE
  {"split",      0, 0, OPT_SPLIT},
#endif
#ifdef IP_TOS
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
  { 0, 0, 0, 0 }
};
static char *short_options;

char srchost[NAMELEN];
const char *dsthost;
display_mode_t display_mode = DisplayAuto;
//

static const char *iface_addr;
//

// If the file stream is associated with a regular file, lock/unlock the file
// in order coordinate writes to a common file from multiple mtr instances
static void locker(FILE *file, short type) {
  if (!file)
    return;
  int fd = fileno(file);
  if (fd < 0) {
    WARN("%s", "fileno()");
    return;
  }
  struct stat stat;
  if (fstat(fd, &stat) < 0) {
    WARN("fstat(%d)", fd);
    return;
  }
  if (!S_ISREG(stat.st_mode))
    return;
  struct flock lock = { .l_whence = SEEK_END, .l_type = type, .l_pid = mypid };
  if (fcntl(fd, F_SETLKW, &lock) < 0) {
    WARN("fcntl(fd=%d, type=%d)", fd, type);
    return;
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
    if (len) oopt[len++] = '|';   \
    oopt[len++] = (ch);           \
  }                               \
} while (0)
#endif

static const char *get_opt_desc(char opt) {
  switch (opt) {
    case OPT_TTLFIRST:
    case OPT_TTLMAX:
#ifdef IP_TOS
    case OPT_QOS:
#endif
    case OPT_BITS:    return STR_NUMBER;
    case OPT_INTERVAL:
    case OPT_CACHE:
    case OPT_TIMEOUT: return STR_IN_SECONDS;
    case OPT_ADDR:    return STR_IP_ADDRESS;
    case OPT_COUNT:    return STR_COUNT;
#ifdef CURSESMODE
    case OPT_DISPLAY: return STR_MODE;
#endif
    case OPT_SIZE:    return STR_IN_BYTES;
    case OPT_FIELDS:  return STR_FIELDS;
#ifdef WITH_IPINFO
    case OPT_IPINFO:  return STR_IP_INFO;
#endif
#ifdef ENABLE_DNS
    case OPT_NS:      return STR_IP_ADDRESS;
#endif
#ifdef OUTPUT_FORMAT
    case OPT_OUTPUT: {
      static char oopt[16];
      uint len = 0;
#ifdef OUTPUT_FORMAT_RAW
      ADD_OCHAR(ORAW);
#endif
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
      return oopt; }
#endif
    default: break;
  }
  return NULL;
}

static void usage(const char *name) {
 { char *bname = strdup(name);
   printf("%s: %s [-", STR_USAGE, bname ? basename(bname) : name);
   if (bname) free(bname); }
  uint len = strlen(short_options);
  for (uint i = 0; i < len; i++)
    if (short_options[i] != ':')
      putchar(short_options[i]);
  printf("] %s ...\n", STR_TARGET);
  for (int i = 0; long_options[i].name; i++) {
    printf("\t[");
    char opt = (char)long_options[i].val;
    if (opt)
      printf("-%c|", opt);
    printf("--%s", long_options[i].name);
    if (long_options[i].has_arg)
      printf(" %s", get_opt_desc(opt));
    printf("]\n");
  }
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
      warnx("%s", MANYNS_WARN);
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

static bool split_hostport(char *buff, char* hostport[2]) {
   if (!buff) return false;
   char *host = trim(buff), *port = NULL;
   if (!host) return false;
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
     if (port) { *port++ = 0; port = trim(port); host = trim(host); } }
   hostport[0] = (host && host[0]) ? host : NULL;
   hostport[1] = (port && port[0]) ? port : NULL;
   return true;
}

#ifdef IP_TOS
#if defined(ENABLE_IPV6) && !defined(IPV6_TCLASS)
#define TOS4TOS(what, tos) do { \
  if ((af == AF_INET6) && tos) { \
    warnx("%s: tos=%d: %s", what, tos, TCLASS6_ERR); \
    tos = 0; \
  } \
} while (0)
#endif
#endif
#ifndef TOS4TOS
#define TOS4TOS(what, tos) NOOP
#endif

#ifdef CURSESMODE
#define VAL_TRU(nth) ((val & (1u << (nth - 1))) ? true : false)
static inline void option_display(char opt) {
  int val = limit_int(0, INT8_MAX, optarg, DISPMODE_ERR, opt);
  curses_mode = (val & ~8) % curses_mode_max;
  ini_opts.chart   = val & 3;    // first two bits
                                 // 3rd reserved
  ini_opts.color   = VAL_TRU(4); // 4th
  ini_opts.audible = VAL_TRU(5); // 5th
  ini_opts.visible = VAL_TRU(6); // 6th
  ini_opts.bell    = VAL_TRU(7); // 7th
}
#undef VAL_TRU
#endif

static inline void option_fields(char opt) {
  if (strnlen(optarg, MAXFLD + 1) > MAXFLD)
    errx(EINVAL, "-%c: %s (%s=%d): %s", opt, OVERFLD_ERR, MAX_STR, MAXFLD, optarg);
  for (int i = 0; optarg[i]; i++) {
    int cnt = 0;
    for (; cnt < stat_max; cnt++)
      if (optarg[i] == stats[cnt].key)
        break;
    if (cnt >= stat_max)
      errx(EINVAL, "-%c: %s: %c", opt, UNKNFLD_ERR, optarg[i]);
  }
  set_fld_active(optarg);
}

#ifdef ENABLE_DNS
static inline void option_ns(char opt) {
  char buff[MAX_ADDRSTRLEN + 6/*:port*/] = {0};
  snprinte(buff, sizeof(buff), "%s", optarg);
  if (!buff[0])
    err(EINVAL, "-%c", opt);
  char* hostport[2] = {0};
  if (!split_hostport(buff, hostport))
    errx(EINVAL, "-%c: %s: %s", opt, PARSE_ERR, buff);
  if (!hostport[1]) hostport[1] = "53";
  struct addrinfo *ns = NULL, hints = {
    .ai_family   = AF_UNSPEC,
    .ai_socktype = SOCK_DGRAM,
    .ai_flags    = AI_NUMERICHOST | AI_NUMERICSERV };
  int rc = getaddrinfo(hostport[0], hostport[1], &hints, &ns);
  if (rc || !ns) {
    if (rc == EAI_SYSTEM)
      err(errno, "%s", "getaddrinfo()");
    errx(EINVAL, "-%c: %s: %s", opt, optarg, gai_strerror(rc));
  }
  if (!set_custom_res(ns))
    errx(EXIT_FAILURE, "-%c: %s: %s", opt, SETNS_ERR, optarg);
  freeaddrinfo(ns);
}
#endif

#ifdef OUTPUT_FORMAT
static inline void option_output(const char *progname) {
  if (ini_opts.cycles <= 0)
    ini_opts.cycles = REPORT_PINGS;
  switch (tolower((int)optarg[0])) {
#ifdef OUTPUT_FORMAT_RAW
    case ORAW:  display_mode = DisplayRaw; ini_opts.rawrep = true; break;
#endif
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
    default: usage(progname); QEXIT(EXIT_FAILURE);
  }
}
#endif

static inline void ineractive_modes(display_mode_t mode) {
  switch (mode) {
    case DisplayReport:
#ifdef OUTPUT_FORMAT_RAW
    case DisplayRaw:
#endif
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

#ifdef OUTPUT_OPTV
static void set_optv(int argc, char **argv) {
  mtr_optc = 0;
  for (int i = 1; (i < argc) && (mtr_optc < ARRAY_LEN(mtr_optv)); i++)
    if (argv[i])
      mtr_optv[mtr_optc++] = argv[i];
}
#endif

static inline void short_set(char opt, const char *progname) {
  switch (opt) {
#ifdef ENABLE_IPV6
    case OPT_IPV4:
    case OPT_IPV6:
      net_settings((opt == OPT_IPV4) ? IPV6_DISABLED : IPV6_ENABLED);
      af_specified = true;
      break;
#endif
    case OPT_ADDR:
      assert(optarg);
      iface_addr = optarg;
      break;
#ifdef ENABLE_DNS
    case OPT_BOTH:
      ini_opts.both = true;
      break;
#endif
    case OPT_BITS:
      assert(optarg);
      ini_opts.pattern = limit_int(-1, UINT8_MAX, optarg, BITPATT_STR, opt);
      break;
    case OPT_COUNT:
      assert(optarg);
      ini_opts.cycles = limit_int(-1, INT_MAX, optarg, CYCLESNO_STR, opt);
      break;
#ifdef CURSESMODE
    case OPT_DISPLAY:
      assert(optarg);
      option_display(opt);
      break;
#endif
#ifdef WITH_MPLS
    case OPT_MPLS:
      ini_opts.mpls = true;
      break;
#endif
    case OPT_TTLFIRST:
      assert(optarg);
      if ((optarg[0] == AUTOTTL) && !optarg[1])
        ini_opts.endpoint = true;
      else
        ini_opts.minttl =
          limit_int(1, ini_opts.maxttl, optarg, MINTTL_STR, opt);
      break;
    case OPT_FIELDS:
      assert(optarg);
      option_fields(opt);
      break;
    case OPT_INTERVAL:
      assert(optarg);
      ini_opts.interval = limit_int(1, INT_MAX, optarg, INTERVAL_STR, opt);
      break;
    case OPT_TTLMAX:
      assert(optarg);
      ini_opts.maxttl =
        limit_int(ini_opts.minttl, MAXHOST - 1, optarg, MAXTTL_STR, opt);
      break;
#ifdef ENABLE_DNS
    case OPT_NODNS:
      ini_opts.dns = false;
      break;
    case OPT_NS:
      assert(optarg);
      option_ns(opt);
      break;
#endif
#ifdef OUTPUT_FORMAT
    case OPT_OUTPUT:
      assert(optarg);
      option_output(progname);
      break;
#endif
#ifdef SPLITMODE
    case OPT_SPLIT:
      display_mode = DisplaySplit;
      break;
#endif
#ifdef IP_TOS
    case OPT_QOS:
      assert(optarg);
      ini_opts.qos = limit_int(0, UINT8_MAX, optarg, QOSTOS_STR, opt);
      TOS4TOS(QOSTOS_STR, ini_opts.qos);
      break;
#endif
    case OPT_REPORT:
      display_mode = DisplayReport;
      if (ini_opts.cycles <= 0)
        ini_opts.cycles = REPORT_PINGS;
      break;
    case OPT_SIZE: {
      assert(optarg);
      int max = MAXPACKET - MINPACKET;
      ini_opts.size = limit_int(-max, max, optarg, PSIZE_STR, opt);
    } break;
    case OPT_SUMMARY:
      ini_opts.stat = true;
      break;
    case OPT_TCP:
      if (mtrtype == IPPROTO_UDP)
        errx(EINVAL, "%s: -%c -%c", MUTEXCL_ERR, OPT_TCP, OPT_UDP);
      net_set_type(IPPROTO_TCP);
      ini_opts.tcp = true;
      break;
    case OPT_TIMEOUT:
      assert(optarg);
      ini_opts.syn =
        limit_int(1, TCPSYN_TOUT_MAX, optarg, TCP_TOUT_STR, opt) * MIL;
      break;
    case OPT_UDP:
      if (mtrtype == IPPROTO_TCP)
        errx(EINVAL, "%s: -%c -%c", MUTEXCL_ERR, OPT_UDP, OPT_TCP);
      net_set_type(IPPROTO_UDP);
      ini_opts.udp = true;
      break;
    case OPT_VERSION:
#ifdef BUILD_OPTIONS
      printf("%s.%s: %s\n", PACKAGE_NAME, GITREV, BUILD_OPTIONS);
#else
      printf("%s.%s\n", PACKAGE_NAME, GITREV);
#endif
      QEXIT(EXIT_SUCCESS);
    case OPT_CACHE:
      assert(optarg);
      ini_opts.cache   = limit_int(1, INT_MAX, optarg, CACHE_TOUT_STR, opt);
      ini_opts.oncache = true;
      break;
#ifdef WITH_IPINFO
    case OPT_LOOKUP:
    case OPT_IPINFO: {
      bool extra = (opt == OPT_IPINFO);
      if (extra) {
        assert(optarg);
        ini_opts.ipinfo = true;
      } else
        ini_opts.asn    = true;
      if (!ipinfo_init(extra ? optarg : ASLOOKUP_DEFAULT))
        QEXIT(EXIT_FAILURE);
      if (!ipinfo_action(ActionNone)) // fail to init
        QEXIT(EXIT_FAILURE);
    } break;
#endif
    default:
      usage(progname);
      QEXIT((opt == OPT_HELP) ? EXIT_SUCCESS : EXIT_FAILURE);
  }
}


static void parse_options(int argc, char **argv) {
  int opt = 0;
  while ((opt = my_getopt_long(argc, argv)) >= 0) {
    short_set((char)opt, argv[0]);
#ifdef OUTPUT_OPTV
    if (opt == OPT_OUTPUT) {
      int arg = tolower((int)optarg[0]);
      if ((arg == OTOON) || (arg == OJSON))
        set_optv(argc, argv);
    }
#endif
  }
  run_opts = ini_opts; // to reflect possible interactive changes
  for (int i = 1, len = 0; (i < optind) && (i < argc) && argv[i] && ((uint)len < sizeof(mtr_args)); i++) {
    int inc = snprinte(mtr_args + len, sizeof(mtr_args) - len, (i > 1) ? " %s" : "%s", argv[i]);
    if (inc < 0) break; else len += inc;
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
    warnx("%s: %s: IPv%c: %s", TARGET_STR, dsthost,
      af == AF_INET ? OPT_IPV4 : OPT_IPV6, NOADDR_ERR);
#else
    warnx("%s: %s: %s", TARGET_STR, dsthost, NOADDR_ERR);
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
    warnx("%s: %s: %s", TARGET_STR, dsthost, strerror(EADDRNOTAVAIL));
  else if (af != ai->ai_family) {
    af = ai->ai_family;
    net_settings((af == AF_INET6) ? IPV6_ENABLED : IPV6_DISABLED);
  }
  return ai;
}
#endif

static bool set_target(const struct addrinfo *res) {
  const struct addrinfo *ai =
#ifdef ENABLE_IPV6
    !af_specified ? find_ai_pref(res) :
#endif
    find_ai_af(res);
  if (!ai) return false;
  //
  t_ipaddr *ipaddr =
#ifdef ENABLE_IPV6
    (af == AF_INET6) ? (t_ipaddr*)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr :
#endif
    ((af == AF_INET) ? (t_ipaddr*)&((struct sockaddr_in  *)ai->ai_addr)->sin_addr  : NULL);
  if (!af || !ipaddr || !net_set_host(ipaddr)) {
    warnx("%s (af=%d)", HOSTENT_ERR, af);
    return false;
  }
  if (iface_addr && !net_set_ifaddr(iface_addr)) {
    warnx("%s: %s", USEADDR_ERR, iface_addr);
    return false;
  }
  return true;
}

#if defined(WITH_UNICODE) && defined(HAVE_LOCALE_H) && defined(HAVE_LANGINFO_H)
static void init_locale(void) {
  setlocale(LC_CTYPE, "");
  if (strcasecmp("UTF-8", nl_langinfo(CODESET)) == 0) { // NOLINT(concurrency-mt-unsafe)
    if (iswprint(L'▁')) {
#ifdef CURSESMODE
      curses_mode_max++;
#endif
      return;
    }
    warnx("%s", UNOPRINT_ERR);
  }
  setlocale(LC_CTYPE, NULL);
}
#define UNICODE_INIT init_locale()
#define UNICODE_FREE setlocale(LC_CTYPE, NULL)
#else
#define UNICODE_INIT NOOP
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
  if (!rr || !idn2ascii) return;
  char *name = NULL;
  rr->rc = idn2ascii(rr->target, &name, 0);
  if (!rr->rc && name) getaddrinfo_e(rr, name);
  else rr->error = IDN_STRERROR(rr->rc);
  if (name) free(name);
}
#endif

static void try_to_resolv(t_res_rc *rr) {
  if (!rr || !rr->target) return;
  getaddrinfo_e(rr, rr->target);
#if !defined(AI_IDN) && (defined(LIBIDN2) || defined(LIBIDN))
  if (rr->rc) {
    idn_resolv(rr, IDN_TO_ASCII_LZ);
    if (rr->rc) idn_resolv(rr, IDN_TO_ASCII_8Z);
  }
#endif
}

static inline void resolv_with_port(t_res_rc *rr, t_res_rc *rr_init) {
  if (!rr)
    return;
  char buff[MAX_ADDRSTRLEN + 6/*:port*/] = {0};
  if (snprinte(buff, sizeof(buff), "%s", dsthost) < 0)
    return;
  char* hostport[2] = {0};
  if (split_hostport(buff, hostport)) {
    limit_error[0] = 0;
    if (hostport[1]) {
      int num = limit_int(1, USHRT_MAX, hostport[1], PORTNUM_STR, -1);
      if (!limit_error[0])
        ini_opts.port = num;
    }
    if (!limit_error[0] && hostport[0] && rr_init) {
      *rr = *rr_init; rr->target = hostport[0];
      try_to_resolv(rr);
    }
  } else
    warnx("%s: %s", PARSE_ERR, buff);
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
  mypid = getpid();
#ifndef HAVE_ARC4RANDOM_UNIFORM
  srand(mypid); // reset random seed
#endif
  for (int i = 0; i < stat_max; i++)
    fld_index[(uint8_t)stats[i].key] = i;
  UNICODE_INIT;
  set_fld_active(NULL);
  parse_options(argc, argv);
  if (optind >= argc) { usage(argv[0]); QEXIT(EXIT_SUCCESS); }
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
  display_start(
#ifdef OUTPUT_FORMAT_TOON
    (argc > optind) ? (argc - optind) : 0
#endif
  );
}

static inline bool main_loop(struct addrinfo *ai, uint nth, uint n_targets) {
  static bool next_target;
  bool success = false;
  if (ai) {
    success = set_target(ai);
    if (success) {
      TOS4TOS(dsthost, run_opts.qos);
      locker(stdout, F_WRLCK);
      if (display_open())
        display_loop();
      else
        warnx("%s", OPENDISP_ERR);
      net_end_transit();
      if ((nth + 1) >= n_targets)
        display_confirm_fin();
      display_close(next_target);
      locker(stdout, F_UNLCK);
      if (!next_target)
        next_target = true;
    }
    freeaddrinfo(ai);
  } else
    warnx("%s: %s", RESFAIL_ERR, dsthost);
  return success;
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
  if (strerr_txt[0] && (display_mode == DisplayCurses))
    warnx("%s", strerr_txt); // duplicate an error cleaned by ncurses
  UNICODE_FREE;
}

#ifdef USE_NLS
static void bind_nls(void) {
  setlocale(LC_ALL, "");
  bindtextdomain(PACKAGE_NAME, LOCALEDIR);
  textdomain(PACKAGE_NAME);
}
#define BIND_NLS bind_nls()
#else
#define BIND_NLS NOOP
#endif


int main(int argc, char **argv) {
#define EXIT_WITH_MSG(msg) { BIND_NLS; errx(EXIT_FAILURE, "%s", msg); }
  // get raw sockets
  if (!net_open())
    EXIT_WITH_MSG(RAWSOCK_ERR);
  // drop permissions if that's set
  if (setgid(getgid()) || setuid(getuid()))
    EXIT_WITH_MSG(DROPPERM_ERR);
  // be sure
  if ((geteuid() != getuid()) || (getegid() != getgid()))
    EXIT_WITH_MSG(DROPPERM_ERR);
#ifdef LIBCAP
  if (!drop_caps())
    EXIT_WITH_MSG(DROPCAP_ERR);
#endif
#undef EXIT_WITH_MSG

  BIND_NLS;
  for (uint i = 0; i < ARRAY_LEN(stats); i++) {
    if (stats[i].name && stats[i].name[0]) {
      stats[i].name  = _(stats[i].name);
      stats[i].len   = ustrlen(stats[i].name);
      if (stats[i].min <= stats[i].len)
        stats[i].min = stats[i].len + 1;
    }
    if (stats[i].hint && stats[i].hint[0])
      stats[i].hint  = _(stats[i].hint);
  }

  main_prep(argc, argv);

  t_res_rc rr_init = { .hints = {
#ifdef ENABLE_IPV6
    .ai_family = af_specified ? af : AF_UNSPEC,
#else
    .ai_family = AF_INET,
#endif
    .ai_socktype = SOCK_DGRAM,
#ifdef AI_IDN
    .ai_flags = AI_IDN,
#endif
  }};
  int defport = ini_opts.port;
  bool success = false;
  uint n_targets = (argc > optind) ? (argc - optind) : 0;
  int ndx = optind;
  for (uint i = 0; (ndx < argc) && argv[ndx]; ndx++, i++) {
    tgterr_txt[0] = 0;
    dsthost = argv[ndx];
    ini_opts.port = defport;
    t_res_rc rr = rr_init;
    rr.target = dsthost;
    try_to_resolv(&rr);
    if (rr.rc && ((mtrtype == IPPROTO_TCP) || (mtrtype == IPPROTO_UDP)))
      resolv_with_port(&rr, &rr_init);
    if (rr.rc)
      warnx("%s: %s: %s", RESFAIL_ERR, dsthost, rr.error ? rr.error : UNKNOWN_ERR);
    else
      success = main_loop(rr.res, i, n_targets);
  }

  main_fin();
  return strerr_txt[0] ? EXIT_FAILURE : !success;
}

