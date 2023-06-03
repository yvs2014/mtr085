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
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <getopt.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "config.h"

#if defined(LOG_DNS) || defined(LOG_IPINFO) || defined(LOG_NET) || defined(LOG_POLL)
#define WITH_SYSLOG 1
#include <syslog.h>
#endif

#ifdef HAVE_LIBIDN2
#include <idn2.h>
#define IDN_TO_ASCII_LZ	idn2_to_ascii_lz
#define IDN_TO_ASCII_8Z	idn2_to_ascii_8z
#elif HAVE_LIBIDN
#include <idna.h>
#define IDN_TO_ASCII_LZ	idna_to_ascii_lz
#define IDN_TO_ASCII_8Z	idna_to_ascii_8z
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

#include "mtr.h"
#include "mtr-poll.h"
#include "net.h"
#include "display.h"
#include "report.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif
#ifdef CURSESMODE
#include "mtr-curses.h"
#endif
#ifdef GRAPHMODE
#include "graphcairo-mtr.h"
#endif
#include "macros.h"

#define REPORT_PINGS 10
#define CACHE_TIMEOUT 60

#define FLD_DEFAULT "LS NABWV"
#ifdef CURSESMODE
static const char fld_jitter[MAXFLD + 1] = "DR AGJMXI";
#endif
static char fld_custom[MAXFLD + 1];
static unsigned fld_index[256]; // key->index backresolv

//// global vars
pid_t mypid;
#define ARGS_LEN 64 /* seem to be enough */
char mtr_args[ARGS_LEN + 1];  // display in curses title
unsigned iargs;               // args passed interactively
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
//
int display_offset;
int curses_mode;      // 1st and 2nd bits
#if defined(CURSESMODE) || defined(GRAPHMODE)
int curses_mode_max = 3;
#endif
int color_mode;       // 4th bit
int audible_bell;     // 5th bit
int visible_bell;     // 6th bit
int target_bell_only; // 7th bit
int mtrtype = IPPROTO_ICMP;	// Use ICMP as default packet type
const char *fld_active;
//
const struct statf statf[] = {
// Key, Remark, Header, Width
  {' ', "<sp>: Space between fields", " ", 1},
  {'L', "L: Loss Ratio",          "Loss",  6},
  {'D', "D: Dropped Packets",     "Drop",  5},
  {'R', "R: Received Packets",    "Rcv",   6},
  {'S', "S: Sent Packets",        "Snt",   6},
  {'N', "N: Newest RTT(ms)",      "Last",  6},
  {'B', "B: Min/Best RTT(ms)",    "Best",  6},
  {'A', "A: Average RTT(ms)",     "Avg",   6},
  {'W', "W: Max/Worst RTT(ms)",   "Wrst",  6},
  {'V', "V: Standard Deviation",  "StDev", 6},
  {'G', "G: Geometric Mean",      "Gmean", 6},
  {'J', "J: Current Jitter",      "Jttr",  5},
  {'M', "M: Jitter Mean/Avg.",    "Javg",  5},
  {'X', "X: Worst Jitter",        "Jmax",  5},
  {'I', "I: Interarrival Jitter", "Jint",  5},
};
const int statf_max = sizeof(statf) / sizeof(statf[0]);
//// end-of-global

#if defined(OUTPUT_FORMAT_RAW) || defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_JSON) || defined(OUTPUT_FORMAT_XML)
#define OUTPUT_FORMAT
#endif

static struct option long_options[] = {
  // Long, HasArgs, Flag, Short
  { "inet",       0, 0, '4' },  // use IPv4
#ifdef ENABLE_IPV6
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
#endif
#ifdef OUTPUT_FORMAT
  { "output",     1, 0, 'o' },  // output format: raw, txt, csv, json, xml
#endif
#ifdef SPLITMODE
  { "split",      0, 0, 'p' },
#endif
  { "port",       1, 0, 'P' },  // target port number for TCP
  { "tos",        1, 0, 'q' },  // typeof service (0..255)
  { "report",     0, 0, 'r' },
  { "psize",      1, 0, 's' },  // packet size
  { "summary",    0, 0, 'S' },  // print send/recv summary at exit
  { "tcp",        0, 0, 't' },  // TCP (default is ICMP)
  { "udp",        0, 0, 'u' },  // UDP (default is ICMP)
  { "version",    0, 0, 'v' },
  { "wide",       0, 0, 'w' },  // wide report (-r)
  { "cache",      1, 0, 'x' },  // enable cache with timeout in seconds (0 means default 60sec)
#ifdef WITH_IPINFO
  { "ipinfo",     1, 0, 'y' },
  { "aslookup",   0, 0, 'z' },
#endif
  { "timeout",    1, 0, 'Z' },  // timeout for TCP sockets
  { 0, 0, 0, 0 }
};
static char *short_options;

char srchost[NAMELEN];
const char *dsthost;
int display_mode = -1;
double wait_time = 1;
bool interactive = true;
long max_ping;
//

static char *iface_addr;
//

#define FLOAT_UPTO 10 /* values > FLOAT_UPTO in integer format */
inline int val2len(double v) { return ((v > 0) && (v < FLOAT_UPTO)) ? (v < 0.1 ? 2 : 1) : 0; }

void set_fld_active(const char *s) { strncpy(fld_custom, s, MAXFLD); fld_active = fld_custom; }
#ifdef CURSESMODE
bool is_custom_fld(void) { return strncmp(fld_active, fld_jitter, MAXFLD) && strncmp(fld_active, FLD_DEFAULT, MAXFLD); }
#endif
#if defined(CURSESMODE) || defined(GRAPHMODE)
void onoff_jitter(void) { int cmp = strncmp(fld_active, fld_jitter, MAXFLD); fld_active = cmp ? fld_jitter : fld_custom; }
#endif

const struct statf* active_statf(unsigned i) {
  if (i > MAXFLD) return NULL;
  unsigned n = fld_index[(uint8_t)fld_active[i]];
  return ((n >= 0) && (n < statf_max)) ? &statf[n] : NULL;
}

char* trim(char *s) {
  char *p = s;
  int l = strlen(p);
  while (l && isspace((int)p[l-1])) // order matters
    p[--l] = 0;
  while (isspace((int)*p))
    p++;
  return p;
}

// If the file stream is associated with a regular file, lock/unlock the file
// in order coordinate writes to a common file from multiple mtr instances
static void locker(FILE *file, short type) {
  if (!file)
    return;
  int fd = fileno(file);
  struct stat buf;
  if (fstat(fd, &buf) < 0) {
    WARN_("fstat(%d)", fd);
    return;
  }
  if (!S_ISREG(buf.st_mode))
    return;
  static struct flock l = { .l_whence = SEEK_END };
  l.l_type = type;
  l.l_pid = mypid;
  if (fcntl(fd, F_SETLKW, &l) < 0)
    WARN_("fcntl(fd=%d, type=%d)", fd, type);
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
    case 'B':
    case 'q':
    case 'P': return "NUMBER";
    case 'i':
    case 'x':
    case 'Z': return "SECONDS";
    case 'a': return "IP.ADD.RE.SS";
    case 'c': return "COUNT";
    case 'd': return "MODE";
    case 's': return "BYTES";
    case 'F': return "FIELDS";
#ifdef OUTPUT_FORMAT
    case 'o': { char _oopt[] =
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
  printf("] HOSTNAME ...\n");
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

int limit_int(const int v0, const int v1, const int v, const char *it) {
  if (v < v0) {
    WARNX_("'%s' is less than %d: %d -> %d", it, v0, v, v0);
    return v0;
  }
  if (v > v1) {
    WARNX_("'%s' is greater than %d: %d -> %d", it, v1, v, v1);
    return v1;
  }
  return v;
}
 
static void parse_options(int argc, char **argv) {
  while (1) {
    int opt = my_getopt_long(argc, argv, NULL);
    if (opt == -1)
      break;

    switch (opt) {
    case '4':
      net_init(0);
      break;
#ifdef ENABLE_IPV6
    case '6':
      net_init(1);
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
      cbitpattern = limit_int(-1, 255, atoi(optarg), "Bit Pattern");
      break;
    case 'c':
      max_ping = atol(optarg);
      break;
#if defined(CURSESMODE) || defined(GRAPHMODE)
    case 'd':
      curses_mode = ((atoi(optarg)) & ~8) % curses_mode_max;
      color_mode = ((atoi(optarg)) & 8) ? 1 : 0;
      audible_bell = ((atoi(optarg)) & 16) ? 1 : 0;
      visible_bell = ((atoi(optarg)) & 32) ? 1 : 0;
      target_bell_only = ((atoi(optarg)) & 64) ? 1 : 0;
      break;
#endif
#ifdef WITH_MPLS
    case 'e':
      enable_mpls = true;
      break;
#endif
    case 'f':
      if (optarg[0] == 'a') {
        endpoint_mode = true;
        break;
      }
      fstTTL = limit_int(1, maxTTL, atoi(optarg), "First TTL");
      break;
    case 'F':
      if (strlen(optarg) >= sizeof(fld_active))
        FAIL_("-F: Too many fields (max=%zd): %s", sizeof(fld_active) - 1, optarg);
      for (int i = 0; optarg[i]; i++) {
        int j = 0;
        for (; j < statf_max; j++)
          if (optarg[i] == statf[j].key)
            break;
        if (j >= statf_max)
          FAIL_("-F: Unknown field identifier '%c'", optarg[i]);
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
      wait_time = atof(optarg);
      if (wait_time <= 0)
        FAIL("-i: Wait time must be positive");
      if (getuid() && (wait_time < 1))
        FAIL("-i: Non-root users cannot set an interval less than one second");
      break;
    case 'm':
      maxTTL = limit_int(1, ((MAXHOST - 1) > maxTTL) ? maxTTL : (MAXHOST - 1), atoi(optarg), "Max TTL");
      break;
#ifdef ENABLE_DNS
    case 'n':
      enable_dns = false;
      break;
#endif
#ifdef OUTPUT_FORMAT
    case 'o':
      max_ping = REPORT_PINGS;
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
    case 'P':
      remoteport = atoi(optarg);
      if (remoteport > 65535 || remoteport < 1)
        FAIL_("-P: Illegal port number %d", remoteport);
      break;
    case 'q':
      tos = atoi(optarg);
      if (tos > 255 || tos < 0)	// error message, should do more checking for valid values
        tos = 0;
      break;
    case 'r':
      display_mode = DisplayReport;
      max_ping = REPORT_PINGS;
      break;
    case 's': {
      int s_val = atoi(optarg);
      cpacketsize = limit_int(MINPACKET, MAXPACKET, abs(s_val), "Packet size");
      if (s_val < 0)
        cpacketsize = -cpacketsize;
      } break;
    case 'S':
      enable_stat_at_exit = true;
      break;
    case 't':
      if (mtrtype == IPPROTO_UDP)
        FAIL("-t and -u are mutually exclusive");
      mtrtype = IPPROTO_TCP;
      break;
    case 'u':
      if (mtrtype == IPPROTO_TCP)
        FAIL("-u and -t are mutually exclusive");
      mtrtype = IPPROTO_UDP;
      break;
    case 'v':
      printf("%s-%s\n", argv[0], MTR_VERSION);
      exit(EXIT_SUCCESS);
    case 'w':
      display_mode = DisplayReport;
      max_ping = REPORT_PINGS;
      report_wide = true;
      break;
    case 'x':
      cache_mode = true;
      cache_timeout = atoi(optarg);
	  if (cache_timeout < 0)
        FAIL_("-x: Cache timeout %d must be positive", cache_timeout);
      else if (cache_timeout == 0)
        cache_timeout = CACHE_TIMEOUT;  // default 60 seconds
      break;
#ifdef WITH_IPINFO
    case 'y':
    case 'z':
      if (!ipinfo_init((opt == 'y') ? optarg : ASLOOKUP_DEFAULT))
        exit(EXIT_FAILURE);
      if (!ipinfo_action(ActionNone)) // don't switch at start
        exit(EXIT_FAILURE);
      break;
#endif
    case 'Z':
      syn_timeout = atoi(optarg) * MIL; // in msec
      break;
    default:
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  for (int i = 1, l = 0; (i < argc) && (l < ARGS_LEN); i++)
    l += snprintf(mtr_args + l, ARGS_LEN - l, " %s", argv[i]);

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


#define IDNA_RESOLV(func) { \
  rc = func(dsthost, &hostname, 0); \
  if (rc == IDNA_SUCCESS) rc = getaddrinfo(hostname, NULL, &hints, &res); \
  else rc_msg = idna_strerror(rc); \
  if (hostname) free(hostname); \
}


static bool set_host(struct addrinfo *res) {
  struct addrinfo *ai;
  for (ai = res; ai; ai = ai->ai_next)
    if (af == ai->ai_family)  // use only the desired AF
      break;
  if (!ai || (af != ai->ai_family)) {  // not found
    WARNX_("Desired address family %d not found", af);
    return false;
  }

  char* alptr[2] = { NULL, NULL };
  if (af == AF_INET)
    alptr[0] = (void*) &(((struct sockaddr_in *)ai->ai_addr)->sin_addr);
#ifdef ENABLE_IPV6
  else if (af == AF_INET6)
    alptr[0] = (void*) &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr);
#endif
  else {
    WARNX_("Unknown address family %d", af);
    return false;
  }
  static struct hostent h;
  memset(&h, 0, sizeof(h));
  h.h_name = ai->ai_canonname;
  h.h_aliases = NULL;
  h.h_addrtype = ai->ai_family;
  h.h_length = ai->ai_addrlen;
  h.h_addr_list = alptr;

  if (!net_set_host(&h)) {
    WARNX("Unable to set host entry");
    return false;
  }
  if (iface_addr && !net_set_ifaddr(iface_addr)) {
    WARNX_("Unable to set interface address \"%s\"", iface_addr);
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


int main(int argc, char **argv) {
  if (!net_open())  // Get the raw sockets first thing, so we can drop to user euid immediately
    FAIL("Unable to get raw sockets");
  if (setgid(getgid()) || setuid(getuid()))  // Now drop to user permissions
    ERRR(EXIT_FAILURE, "Unable to drop permissions");
  if ((geteuid() != getuid()) || (getegid() != getgid())) // Double check, just in case
    FAIL("Unable to drop permissions");
  net_assert();

  mypid = getpid();
#ifndef HAVE_ARC4RANDOM_UNIFORM
  srand(mypid); // reset the random seed
#endif

  // initialiaze fld_index
  memset(fld_index, -1, sizeof(fld_index)); // any value > statf_max
  for (int i = 0; i < statf_max; i++)
    fld_index[(uint8_t)statf[i].key] = i;

#ifdef WITH_UNICODE
  autotest_unicode_print();
#endif
  set_fld_active(FLD_DEFAULT);
  parse_options(argc, argv);

  if (optind >= argc) {
    usage(argv[0]);
    exit(EXIT_SUCCESS);
  }

#ifdef WITH_SYSLOG
  openlog(PACKAGE_NAME, LOG_PID, LOG_USER);
#endif
#ifdef ENABLE_IPV6
  net_setsocket6();
#endif
#ifdef ENABLE_DNS
  if (enable_dns)
    dns_open();
#endif
  if (gethostname(srchost, sizeof(srchost)))
    strncpy(srchost, "UNKNOWN", sizeof(srchost));
  display_start();

  for (; optind < argc; optind++) {
    static bool notfirst;
    if (!(dsthost = argv[optind]))
      continue;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_DGRAM;
    int rc = getaddrinfo(dsthost, NULL, &hints, &res);
    const char *rc_msg = NULL;
#if defined(HAVE_LIBIDN) || defined(HAVE_LIBIDN2)
    if (rc) {
      char *hostname = NULL;
      IDNA_RESOLV(IDN_TO_ASCII_LZ);
      if (rc)
        IDNA_RESOLV(IDN_TO_ASCII_8Z);
    }
#endif
    if (rc) {
      if (rc == EAI_SYSTEM)
        WARN_("getaddrinfo(%s)", dsthost);
      else
        WARNX_("Failed to resolve \"%s\": %s", dsthost, rc_msg ? rc_msg : gai_strerror(rc));
    } else {
      if (set_host(res)) {
        locker(stdout, F_WRLCK);
        if (display_open())
          display_loop();
        else
          WARNX("Unable to open display");
        net_end_transit();
        display_close(notfirst);
        locker(stdout, F_UNLCK);
      }
      freeaddrinfo(res);
    }
    notfirst = true;
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
  return 0;
}

