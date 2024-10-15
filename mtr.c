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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <libgen.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <netinet/in.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#endif

#include "common.h"

#ifdef LIBCAP
#include <sys/capability.h>
#endif

#if defined(LOG_DNS) || defined(LOG_IPINFO) || defined(LOG_NET) || defined(LOG_POLL)
#define WITH_SYSLOG 1
#include <syslog.h>
#endif

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

#if defined(OUTPUT_FORMAT_RAW) || defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_JSON) || defined(OUTPUT_FORMAT_XML)
#define OUTPUT_FORMAT
#include <ctype.h>
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
#ifdef GRAPHMODE
#include "graphcairo-mtr.h"
#endif
#ifdef OUTPUT_FORMAT_RAW
#include "report.h"
#endif

#define REPORT_PINGS 100
#define CACHE_TIMEOUT 60
#define TCPSYN_TOUT_MAX 60

//// global vars
int mtrtype = IPPROTO_ICMP;   // ICMP as default packet type
pid_t mypid;
#define ARGS_LEN 64 /* seem to be enough */
char mtr_args[ARGS_LEN + 1];  // display in curses title
unsigned run_args;            // runtime args to display hints
unsigned kept_args;           // kept args mapped in bits

#ifdef ENABLE_IPV6
static bool af_specified; // set with -4/-6 options
#endif
#ifdef ENABLE_DNS
bool show_ips;
#endif
#ifdef WITH_MPLS
bool enable_mpls;
#endif
bool report_wide;
bool endpoint_mode;           // -fa option, i.e. auto, corresponding to TTL of the destination host
bool cache_mode;              // don't ping known hops
int cache_timeout = CACHE_TIMEOUT;  // cache timeout in seconds
bool enable_stat_at_exit;
int fstTTL = 1;	              // default start at first hop
int maxTTL = 30;              // enough?
int remoteport = -1;          // target port
int tos;                      // type of service set in ping packet
int cbitpattern;              // payload bit pattern
int cpacketsize = 64;         // default packet size
int syn_timeout = MIL;        // for TCP tracing (1sec in msec)
int sum_sock[2];              // socket summary: open()/close() calls
int last_neterr;              // last known network error
char neterr_txt[ERRBYFN_SZ];  // buff for 'last_neterr'
// chart related
int display_offset;
int curses_mode;              // 1st and 2nd bits, 3rd is reserved
#if defined(CURSESMODE) || defined(GRAPHMODE)
int curses_mode_max = 3;
#endif
bool enable_color;            // 4th bit
bool bell_audible;            // 5th bit
bool bell_visible;            // 6th bit
bool bell_target;             // 7th bit
//
const struct statf statf[] = {
// name     hint                    len key
  {" ",     "Space between fields", 1,  '_'},
  {"Loss",  "Loss Ratio",           6,  'L'},
  {"Drop",  "Dropped Packets",      5,  'D'},
  {"Rcv",   "Received Packets",     6,  'R'},
  {"Snt",   "Sent Packets",         6,  'S'},
  {"Last",  "Newest RTT(ms)",       6,  'N'},
  {"Best",  "Min/Best RTT(ms)",     6,  'B'},
  {"Avg",   "Average RTT(ms)",      6,  'A'},
  {"Wrst",  "Max/Worst RTT(ms)",    6,  'W'},
  {"StDev", "Standard Deviation",   6,  'V'},
  {"Gmean", "Geometric Mean",       6,  'G'},
  {"Jttr",  "Current Jitter",       5,  'J'},
  {"Javg",  "Jitter Mean/Avg.",     5,  'M'},
  {"Jmax",  "Worst Jitter",         5,  'X'},
  {"Jint",  "Interarrival Jitter",  5,  'I'},
};
const int statf_max = sizeof(statf) / sizeof(statf[0]);
//// end-of-global

static struct option long_options[] = {
  // Long, HasArgs, Flag, Short
#ifdef ENABLE_IPV6
  { "inet",       0, 0, '4' },  // use IPv4
  { "inet6",      0, 0, '6' },  // use IPv6
#endif
  { "address",    1, 0, 'a' },
#ifdef ENABLE_DNS
  { "show-ips",   0, 0, 'b' },
#endif
  { "bitpattern", 1, 0, 'B' },   // in range 0-255, or -1 for random
  { "cycles",     1, 0, 'c' },
#if defined(CURSESMODE) || defined(GRAPHMODE)
  { "display",    1, 0, 'd' },
#endif
#ifdef WITH_MPLS
  { "mpls",       0, 0, 'e' },
#endif
  { "first-ttl",  1, 0, 'f' },   // -f and -m are borrowed from traceroute
  { "fields",     1, 0, 'F' },   // fields to display and their order
#ifdef GRAPHMODE
  { "graph",      1, 0, 'g' },
#endif
  { "help",       0, 0, 'h' },
  { "interval",   1, 0, 'i' },
  { "max-ttl",    1, 0, 'm' },
#ifdef ENABLE_DNS
  { "no-dns",     0, 0, 'n' },
  { "ns",         1, 0, 'N' },
#endif
#ifdef OUTPUT_FORMAT
  { "output",     1, 0, 'o' },  // output format: raw, txt, csv, json, xml
#endif
#ifdef SPLITMODE
  { "split",      0, 0, 'p' },
#endif
#ifdef IP_TOS
  { "tos",        1, 0, 'q' },  // type of service (0..255)
#endif
  { "report",     0, 0, 'r' },
  { "psize",      1, 0, 's' },  // packet size
  { "summary",    0, 0, 'S' },  // print send/recv summary at exit
  { "tcp",        0, 0, 't' },  // TCP (default is ICMP)
  { "timeout",    1, 0, 'T' },  // timeout for TCP sockets
  { "udp",        0, 0, 'u' },  // UDP (default is ICMP)
  { "version",    0, 0, 'v' },
  { "wide",       0, 0, 'w' },  // wide report (-r)
  { "cache",      1, 0, 'x' },  // enable cache with timeout in seconds (0 means default 60sec)
#ifdef WITH_IPINFO
  { "ipinfo",     1, 0, 'y' },
  { "aslookup",   0, 0, 'z' },
#endif
  { 0, 0, 0, 0 }
};
static char *short_options;

char srchost[NAMELEN];
const char *dsthost;
int display_mode = -1;
double wait_time = 1;
bool interactive = true;
long max_ping = REPORT_PINGS;  // 0 should be set explicitly
//

static const char *iface_addr;
//

// If the file stream is associated with a regular file, lock/unlock the file
// in order coordinate writes to a common file from multiple mtr instances
static void locker(FILE *file, short type) {
  if (!file)
    return;
  int fd = fileno(file);
  struct stat buf;
  if (fstat(fd, &buf) < 0) {
    WARN("fstat(%d)", fd);
    return;
  }
  if (!S_ISREG(buf.st_mode))
    return;
  static struct flock l = { .l_whence = SEEK_END };
  l.l_type = type;
  l.l_pid = mypid;
  if (fcntl(fd, F_SETLKW, &l) < 0)
    WARN("fcntl(fd=%d, type=%d)", fd, type);
}

static int my_getopt_long(int argc, char *argv[], int *opt_ndx) {
  if (!short_options) {
    short_options = calloc((sizeof(long_options) / sizeof(long_options[0])) * 2 + 1, 1);
    if (!short_options)
      return -1;
    char *p = short_options;
    for (int i = 0; long_options[i].name; i++) {
      *p++ = (char)long_options[i].val;
      if (long_options[i].has_arg)
        *p++ = ':';
    }
  }
  return getopt_long(argc, argv, short_options, long_options, opt_ndx);
}

static const char *get_opt_desc(char opt) {
  switch (opt) {
    case 'm':
    case 'f':
#ifdef IP_TOS
    case 'q':
#endif
    case 'B': return "NUMBER";
    case 'i':
    case 'x':
    case 'T': return "SECONDS";
    case 'a': return "IP.ADD.RE.SS";
    case 'c': return "COUNT";
    case 'd': return "MODE";
    case 's': return "BYTES";
    case 'F': return "FIELDS";
#ifdef ENABLE_DNS
    case 'N': return "NS.ADD.RE.SS";
#endif
#ifdef OUTPUT_FORMAT
    case 'o': { static char _oopt[] =
#ifdef OUTPUT_FORMAT_RAW
" RAW"
#endif
#ifdef OUTPUT_FORMAT_TXT
" TXT"
#endif
#ifdef OUTPUT_FORMAT_CSV
" CSV"
#endif
#ifdef OUTPUT_FORMAT_JSON
" JSON"
#endif
#ifdef OUTPUT_FORMAT_XML
" XML"
#endif
    ; return trim(_oopt); }
#endif
#ifdef WITH_IPINFO
    case 'y': return "ORIGIN,FIELDS";
#endif
#ifdef GRAPHMODE
    case 'g': return "type,period,legend,multipath,jitter";
#endif
  }
  return NULL;
}

static void usage(const char *name) {
  char *bname = strdup(name);
  printf("Usage: %s [-", basename(bname));
  int l = strlen(short_options);
  for (int i = 0; i < l; i++)
    if (short_options[i] != ':')
      putchar(short_options[i]);
  printf("] TARGET[:PORT] ...\n");
  for (int i = 0; long_options[i].name; i++) {
    printf("\t[");
    char c = (char)long_options[i].val;
    if (c)
      printf("-%c|", c);
    printf("--%s", long_options[i].name);
    const char *desc = long_options[i].has_arg ? get_opt_desc(c) : NULL;
    if (desc)
      printf(" %s", desc);
    printf("]\n");
  }
  free(bname);
}

char limit_error[256];
int limit_int(int min, int max, int val, const char *what, char fail) {
  limit_error[0] = 0;
  int lim = val, l = 0;
  if (val < min) {
    lim = min;
    l = snprintf(limit_error, sizeof(limit_error), "%s is less than %d", what, min);
  } else if (val > max) {
    lim = max;
    l = snprintf(limit_error, sizeof(limit_error), "%s is greater than %d", what, max);
  }
  if (val != lim) {
    if (fail > 0) { warnx("%s", limit_error); errx(EXIT_FAILURE, "-%c option failed", fail); }
    else if (fail < 0) warnx("%s", limit_error);
    else snprintf(limit_error + l, sizeof(limit_error) - l, ", corrected(%d -> %d)", val, lim);
  }
  return lim;
}

#ifdef ENABLE_DNS
static bool set_custom_res(struct addrinfo *ns) {
  if (ns && ns->ai_addr && ns->ai_family &&
#ifdef ENABLE_IPV6
      ((ns->ai_family == AF_INET6) ? addr6exist(&((struct sockaddr_in6 *)ns->ai_addr)->sin6_addr) :
#endif
      ((ns->ai_family == AF_INET) ? addr4exist(&((struct sockaddr_in *)ns->ai_addr)->sin_addr) : false))) {
    if (custom_res) { free(custom_res); WARNX("NS is aready set, setting a new one ..."); }
    custom_res = malloc(sizeof(*custom_res));
    if (custom_res) {
      memcpy(custom_res, ns->ai_addr, ns->ai_addrlen);
      uint16_t *port =
#ifdef ENABLE_IPV6
        (ns->ai_family == AF_INET6) ? &custom_res->S6PORT :
#endif
        ((ns->ai_family == AF_INET) ? &custom_res->S_PORT : NULL);
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
     if (!port) { warnx("Failed to parse hostport literal: %s", buff); return false; }
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
#define TOS4TOS(what) do { \
  if ((af == AF_INET6) && tos) \
    warnx("%s: tos=%d: IPv6 traffic class is not supported", what, tos); \
} while (0)
#endif
#endif
#ifndef TOS4TOS
#define TOS4TOS(what) NOOP
#endif

static void parse_options(int argc, char **argv) {
  SETBIT(kept_args, RA_DNS); // dns is on by default

  while (1) {
    int opt = my_getopt_long(argc, argv, NULL);
    if (opt == -1)
      break;

    switch (opt) {
#ifdef ENABLE_IPV6
    case '4':
      net_settings(IPV6_DISABLED);
      af_specified = true;
      break;
    case '6':
      net_settings(IPV6_ENABLED);
      af_specified = true;
      break;
#endif
    case '?':
      usage(argv[0]);
      exit(EXIT_FAILURE);
    case 'a':
      iface_addr = optarg;
      break;
#ifdef ENABLE_DNS
    case 'b':
      show_ips = true;
      break;
#endif
    case 'B':
      cbitpattern = limit_int(-1, 255, atoi(optarg), "Bit Pattern", opt);
      break;
    case 'c':
      max_ping = atol(optarg);
      break;
#if defined(CURSESMODE) || defined(GRAPHMODE)
    case 'd': {
      int v = atoi(optarg);
      curses_mode = (v & ~8) % curses_mode_max;
      enable_color = v & 8;
      bell_audible = v & 16;
      bell_visible = v & 32;
      bell_target  = v & 64;
      // chart mode bits
      if (v & 1) kept_args |= RA_DM0;
      if (v & 2) kept_args |= RA_DM1;
      } break;
#endif
#ifdef WITH_MPLS
    case 'e':
      enable_mpls = true;
      SETBIT(kept_args, RA_MPLS)
      break;
#endif
    case 'f':
      if (optarg[0] == 'a') {
        endpoint_mode = true;
        break;
      }
      fstTTL = limit_int(1, maxTTL, atoi(optarg), "First TTL", opt);
      break;
    case 'F':
      if (strlen(optarg) >= sizeof(fld_active))
        FAIL("-F: Too many fields (max=%zd): %s", sizeof(fld_active) - 1, optarg);
      for (int i = 0; optarg[i]; i++) {
        int j = 0;
        for (; j < statf_max; j++)
          if (optarg[i] == statf[j].key)
            break;
        if (j >= statf_max)
          FAIL("-F: Unknown field identifier '%c'", optarg[i]);
      }
      set_fld_active(optarg);
      break;
#ifdef GRAPHMODE
    case 'g':
      if (!gc_parsearg(optarg))
        exit(EXIT_FAILURE);
      display_mode = DisplayGraphCairo;
      break;
#endif
    case 'h':
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    case 'i':
      wait_time = limit_int(1, INT_MAX, atoi(optarg), "interval", opt);
      break;
    case 'm':
      maxTTL = limit_int(fstTTL, MAXHOST - 1, atoi(optarg), "Max TTL", opt);
      break;
#ifdef ENABLE_DNS
    case 'n':
      enable_dns = false;
      CLRBIT(kept_args, RA_DNS);
      break;
    case 'N': {
      char buff[MAX_ADDRSTRLEN + 6/*:port*/] = {0};
      STRLCPY(buff, optarg, sizeof(buff));
      char* hostport[2] = {0};
      if (!split_hostport(buff, hostport)) FAIL("Failed to parse NS(%s)", buff);
      if (!hostport[1]) hostport[1] = "53";
      struct addrinfo *ns, hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_flags    = AI_NUMERICHOST | AI_NUMERICSERV };
      int rc = getaddrinfo(hostport[0], hostport[1], &hints, &ns);
      if (rc || !ns) {
        if (rc == EAI_SYSTEM) FAIL("getaddrinfo()");
        FAIL("Failed to set NS(%s): %s", optarg, gai_strerror(rc));
      }
      if (!set_custom_res(ns)) FAIL("Failed to set NS(%s)", optarg);
      freeaddrinfo(ns);
    } break;
#endif
#ifdef OUTPUT_FORMAT
    case 'o':
      if (max_ping <= 0) max_ping = REPORT_PINGS;
      switch (tolower((int)optarg[0])) {
#ifdef OUTPUT_FORMAT_RAW
        case 'r':
          display_mode = DisplayRaw;
          enable_raw = true;
          break;
#endif
#ifdef OUTPUT_FORMAT_TXT
        case 't':
          display_mode = DisplayTXT;
          break;
#endif
#ifdef OUTPUT_FORMAT_CSV
        case 'c':
          display_mode = DisplayCSV;
          break;
#endif
#ifdef OUTPUT_FORMAT_JSON
        case 'j':
          display_mode = DisplayJSON;
          break;
#endif
#ifdef OUTPUT_FORMAT_XML
        case 'x':
          display_mode = DisplayXML;
          break;
#endif
        default:
          usage(argv[0]);
          exit(EXIT_FAILURE);
      }
      break;
#endif
#ifdef SPLITMODE
    case 'p':
      display_mode = DisplaySplit;
      break;
#endif
#ifdef IP_TOS
    case 'q':
      tos = limit_int(0, 255, atoi(optarg), "Type of Service (ToS)", opt);
      TOS4TOS("option -q");
      break;
#endif
    case 'r':
      display_mode = DisplayReport;
      if (max_ping <= 0) max_ping = REPORT_PINGS;
      break;
    case 's': {
      int sz = atoi(optarg);
      cpacketsize = limit_int(MINPACKET, MAXPACKET, abs(sz), "Packet size", opt);
      if (sz < 0) cpacketsize = -cpacketsize;
    } break;
    case 'S':
      enable_stat_at_exit = true;
      break;
    case 't':
      if (mtrtype == IPPROTO_UDP)
        FAIL("-t and -u are mutually exclusive");
      net_set_type(IPPROTO_TCP);
      SETBIT(kept_args, RA_TCP)
      break;
    case 'T':
      syn_timeout = limit_int(1, TCPSYN_TOUT_MAX, atoi(optarg), "TCP timeout", opt) * MIL;
      break;
    case 'u':
      if (mtrtype == IPPROTO_TCP)
        FAIL("-u and -t are mutually exclusive");
      net_set_type(IPPROTO_UDP);
      SETBIT(kept_args, RA_UDP)
      break;
    case 'v':
#ifdef BUILD_OPTIONS
      printf("%s: %s\n", FULLNAME, BUILD_OPTIONS);
#else
      printf("%s\n", FULLNAME);
#endif
      exit(EXIT_SUCCESS);
    case 'w':
      display_mode = DisplayReport;
      if (max_ping <= 0) max_ping = REPORT_PINGS;
      report_wide = true;
      break;
    case 'x':
      cache_mode = true;
      cache_timeout = atoi(optarg);
      if (cache_timeout < 0)
        FAIL("-x: Cache timeout %d must be positive", cache_timeout);
      else if (cache_timeout == 0)
        cache_timeout = CACHE_TIMEOUT;  // default 60 seconds
      SETBIT(kept_args, RA_CACHE)
      break;
#ifdef WITH_IPINFO
    case 'y':
      SETBIT(kept_args, RA_IPINFO)
    case 'z':
      SETBIT(kept_args, RA_ASN)
      if (!ipinfo_init((opt == 'y') ? optarg : ASLOOKUP_DEFAULT))
        exit(EXIT_FAILURE);
      if (!ipinfo_action(ActionNone)) // don't switch at start
        exit(EXIT_FAILURE);
      break;
#endif
    default:
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }
  run_args = kept_args; // for displaying runtime changes

  for (int i = 1, l = 0; (i < optind) && (l < ARGS_LEN); i++)
    l += snprintf(mtr_args + l, ARGS_LEN - l, (i != 1) ? " %s" : "%s" , argv[i]);

  switch (display_mode) {
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
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
      interactive = false;
  }
}


static bool set_target(struct addrinfo *res) {
  struct addrinfo *ai;
#ifdef ENABLE_IPV6
  if (af_specified) {
#endif
    for (ai = res; ai; ai = ai->ai_next)
      if (ai->ai_family == af)  // use only the desired AF
        break;
    if (!ai || (ai->ai_family != af)) {  // not found
      warnx("target(%s): No address found for IPv%c (AF %d)", dsthost, af == AF_INET ? '4' : '6', af);
      return false;
    }
#ifdef ENABLE_IPV6
  } else { // preference: first ipv4, second ipv6
    for (ai = res; ai; ai = ai->ai_next) if (ai->ai_family == AF_INET) break;
    if (!ai)
      for (ai = res; ai; ai = ai->ai_next) if (ai->ai_family == AF_INET6) break;
    if (!ai) {
      warnx("target(%s): No address found", dsthost);
      return false;
    }
    if (af != ai->ai_family) {
      af = ai->ai_family;
      net_settings((af == AF_INET6) ? IPV6_ENABLED : IPV6_DISABLED);
    }
  }
#endif

  t_ipaddr *ipaddr =
#ifdef ENABLE_IPV6
    (af == AF_INET6) ? (t_ipaddr*)&((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr :
#endif
    ((af == AF_INET) ? (t_ipaddr*)&((struct sockaddr_in *)ai->ai_addr)->sin_addr : NULL);
  if (!af || !ipaddr || !net_set_host(ipaddr)) {
    WARNX("Unable to set host entry (af=%d)", af);
    return false;
  }
  if (iface_addr && !net_set_ifaddr(iface_addr)) {
    WARNX("Unable to set interface address(%s)", iface_addr);
    return false;
  }
  return true;
}

#ifdef WITH_UNICODE
void autotest_unicode_print(void) {
#if defined(HAVE_LOCALE_H) && defined(HAVE_LANGINFO_H)
  setlocale(LC_CTYPE, "");
  if (strcasecmp("UTF-8", nl_langinfo(CODESET)) == 0) {
    if (iswprint(L'▁')) {
      curses_mode_max++;
      return;
    }
    WARNX("Unicode block elements are not printable");
  }
  setlocale(LC_CTYPE, NULL);
#endif
}
#endif

#ifdef LIBCAP
static bool reset_caps(void) {
  bool re = false;
  cap_t cap = cap_init();
  if (cap) {
    re = cap_set_proc(cap) == 0;
    if (!re) WARN("cap_set_proc");
    cap_free(cap);
  } else WARN("cap_init");
  return re;
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
    (rr->rc == EAI_SYSTEM) ? strerror(errno) : gai_strerror(rr->rc);
}

#if defined(LIBIDN2) || defined(LIBIDN)
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
#if defined(LIBIDN2) || defined(LIBIDN)
  if (rr->rc) {
    idn_resolv(rr, IDN_TO_ASCII_LZ);
    if (rr->rc) idn_resolv(rr, IDN_TO_ASCII_8Z);
  }
#endif
}


int main(int argc, char **argv) {
  if (!net_open()) // get raw sockets
    FAIL("Unable to get raw sockets");
  if (setgid(getgid()) || setuid(getuid())) // drop permissions if that's set
    ERRR(EXIT_FAILURE, "Unable to drop permissions");
  if ((geteuid() != getuid()) || (getegid() != getgid())) // just in case
    FAIL("Unable to drop permissions");
#ifdef LIBCAP
  if (!reset_caps())
    FAIL("Unable to reset capabilities");
#endif
  net_assert();

  mypid = getpid();
#ifndef HAVE_ARC4RANDOM_UNIFORM
  srand(mypid); // reset the random seed
#endif

  for (int i = 0; i < statf_max; i++)
    fld_index[(uint8_t)statf[i].key] = i;

#ifdef WITH_UNICODE
  autotest_unicode_print();
#endif
  set_fld_active(NULL);
  parse_options(argc, argv);

  if (optind >= argc) {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

#ifdef WITH_SYSLOG
  openlog(PACKAGE_NAME, LOG_PID, LOG_USER);
#endif
#ifdef ENABLE_IPV6
  net_setsock6();
#endif
#ifdef ENABLE_DNS
  if (enable_dns)
    dns_open();
#endif
  if (gethostname(srchost, sizeof(srchost)))
    STRLCPY(srchost, "UNKNOWN", sizeof(srchost));
  display_start();

  int defport = remoteport;
  bool first = true, set_target_success = false;
  for (; optind < argc; optind++) {
    if (!(dsthost = argv[optind]))
      continue;
    remoteport = defport;
    t_res_rc rr0 = {.hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM}};
    t_res_rc rr = rr0; rr.target = dsthost;
    try_to_resolv(&rr);
    if (rr.rc && ((mtrtype == IPPROTO_TCP) || (mtrtype == IPPROTO_UDP))) {
      char buff[MAX_ADDRSTRLEN + 6/*:port*/] = {0};
      STRLCPY(buff, dsthost, sizeof(buff));
      char* hostport[2] = {0};
      if (split_hostport(buff, hostport)) {
        limit_error[0] = 0;
        if (hostport[1]) remoteport = limit_int(1, 65535, atoi(hostport[1]), "port number", -1);
        if (!limit_error[0]) {
          rr = rr0; rr.target = hostport[0];
          try_to_resolv(&rr);
        }
      } else warn("Failed to parse(%s)", buff);
    }
    if (rr.rc)
      warnx("Failed to resolve(%s): %s", dsthost, rr.error ? rr.error : "Unknown error");
    else if (rr.res) {
      if ((set_target_success = set_target(rr.res))) {
        TOS4TOS(dsthost);
        locker(stdout, F_WRLCK);
        if (display_open(!first)) display_loop();
        else WARNX("Unable to open display");
        net_end_transit();
        display_close(!first);
        locker(stdout, F_UNLCK);
      }
      freeaddrinfo(rr.res);
    } else warnx("Cannot get resolv data(%s)", dsthost);
    if (first) first = false;
  }

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

  if (enable_stat_at_exit) {
    printf("SOCKET: %u opened, %u closed\n", sum_sock[0], sum_sock[1]);
    printf("NET: %lu queries (%lu icmp, %lu udp, %lu tcp), %lu replies (%lu icmp, %lu udp, %lu tcp)\n",
      net_queries[0], net_queries[1], net_queries[2], net_queries[3],
      net_replies[0], net_replies[1], net_replies[2], net_replies[3]);
#ifdef ENABLE_DNS
    printf("DNS: %u queries (%u ptr, %u txt), %u replies (%u ptr, %u txt)\n",
      dns_queries[0], dns_queries[1], dns_queries[2],
      dns_replies[0], dns_replies[1], dns_replies[2]);
#endif
#ifdef WITH_IPINFO
    printf("IPINFO: %u queries (%u http, %u whois), %u replies (%u http, %u whois)\n",
      ipinfo_queries[0], ipinfo_queries[1], ipinfo_queries[2],
      ipinfo_replies[0], ipinfo_replies[1], ipinfo_replies[2]);
#endif
  }

  if (last_neterr && (display_mode == DisplayCurses))
    warnx("%s", neterr_txt); // duplicate an error cleaned by ncurses
  return last_neterr || !set_target_success;
}

