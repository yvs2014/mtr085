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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "config.h"

#ifdef HAVE_LIBIDN2
#include <idn2.h>
#define IDN_TO_ASCII_LZ	idn2_to_ascii_lz
#define IDN_TO_ASCII_8Z	idn2_to_ascii_8z
#elif HAVE_LIBIDN
#include <idna.h>
#define IDN_TO_ASCII_LZ	idna_to_ascii_lz
#define IDN_TO_ASCII_8Z	idna_to_ascii_8z
#endif

#ifdef UNICODE
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

#ifdef CURSES
#include "mtr-curses.h"
#endif
#include "getopt.h"
#include "display.h"
#include "dns.h"
#include "report.h"
#include "net.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif
#ifdef GRAPHCAIRO
#include "graphcairo-mtr.h"
#endif
#include "version.h"

typedef struct names {
	char*		name;
	struct names*	next;
} names_t;

#define CACHE_TIMEOUT	60

// global vars
pid_t mypid;
char mtr_args[1024];	// posix/susvn: 4096+
unsigned iargs;		// args passed interactively
bool show_ips = false;
bool enable_mpls = false;
bool report_wide = false;
bool endpoint_mode = false; // -fa option, i.e. auto, corresponding to TTL of the destination host
bool cache_mode = false;            // don't ping known hops
int cache_timeout = CACHE_TIMEOUT;  // cache timeout in seconds
bool hinit = false;	// make sure that a hashtable already exists or not
int fstTTL = 1;		// default start at first hop
int maxTTL = 30;	// enough?
int bitpattern;	// packet bit pattern used by ping
int remoteport = -1;	// target port
int tos;	// type of service set in ping packet
int cpacketsize = 64;	// default packet size
int tcp_timeout = 10 * 1000000;	// for TCP tracing
//
int display_offset;
int curses_mode;	// 1st and 2nd bits
#if defined(CURSES) || defined(GRAPHCAIRO)
int curses_mode_max = 3;
#endif
int color_mode;	// 4th bit
int audible_bell;	// 5th bit
int visible_bell;	// 6th bit
int target_bell_only;	// 7th bit
int mtrtype = IPPROTO_ICMP;	// Use ICMP as default packet type
	// default display field and order
int fld_index[256];
char fld_avail[AVLFLD + 1];
FLD_BUF_T fld_active;
FLD_BUF_T fld_save;
const struct fields data_fields[AVLFLD + 1] = {
	// Key, Remark, Header, Format, Width
	{' ', "<sp>: Space between fields", " ",  " ",        1},
	{'L', "L: Loss Ratio",          "Loss",   " %4.1f%%", 6},
	{'D', "D: Dropped Packets",     "Drop",   " %4d",     5},
	{'R', "R: Received Packets",    "Rcv",    " %5d",     6},
	{'S', "S: Sent Packets",        "Snt",    " %5d",     6},
	{'N', "N: Newest RTT(ms)",      "Last",   " %5.1f",   6},
	{'B', "B: Min/Best RTT(ms)",    "Best",   " %5.1f",   6},
	{'A', "A: Average RTT(ms)",     "Avg",    " %5.1f",   6},
	{'W', "W: Max/Worst RTT(ms)",   "Wrst",   " %5.1f",   6},
	{'V', "V: Standard Deviation",  "StDev",  " %5.1f",   6},
	{'G', "G: Geometric Mean",      "Gmean",  " %5.1f",   6},
	{'J', "J: Current Jitter",      "Jttr",   " %4.1f",   5},
	{'M', "M: Jitter Mean/Avg.",    "Javg",   " %4.1f",   5},
	{'X', "X: Worst Jitter",        "Jmax",   " %4.1f",   5},
	{'I', "I: Interarrival Jitter", "Jint",   " %4.1f",   5},
	{'\0', NULL, NULL, NULL, 0}
};
	//
char srchost[NAMELEN];
char *dsthost = NULL;
int display_mode;
float wait_time = 1.0;
bool interactive = true;
int max_ping = 10;
bool alter_ping = false;
//

static char *iface_addr = NULL;
static names_t *names = NULL;

#if defined(OUTPUT_FORMAT_RAW) || defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_JSON) || defined(OUTPUT_FORMAT_XML)
#define OUTPUT_FORMAT
#endif

void set_fld_active(const char *s) {
  static FLD_BUF_T s_copy;
  strncpy((char*)s_copy, s, sizeof(s_copy) - 1);
  memset(fld_save, 0, sizeof(fld_save));
  strncpy((char*)fld_save, (char*)fld_active, sizeof(fld_save));
  memset(fld_active, 0, sizeof(fld_active));
  strncpy((char*)fld_active, (char*)s_copy, sizeof(fld_active));
}

// type must correspond 'id' in resolve HEADER (unsigned id:16)
// it's used as a hint for fast search, 16bits as [hash:7 at:6 ndx:3]
uint16_t str2hint(const char* s, int16_t at, uint16_t ndx) {
  uint16_t h = 0, c;
  while ((c = *s++))
    h = ((h << 5) + h) ^ c; // h * 33 ^ c
  h &= IDMASK;
  h |= AT2ID(at);
  h |= ID2NDX(ndx);
  return h;
}

uint16_t str2dnsid(const char* s) {
  uint16_t h = 0, c;
  while ((c = *s++))
    h = ((h << 5) + h) ^ c; // h * 33 ^ c
  return h;
}

char* trim(char *s) {
  char *p = s;
  int l = strlen(p);
  while (isspace((int)p[l-1]) && l)
    p[--l] = 0;
  while (isspace((int)*p))
    p++;
  return p;
}

static void append_to_names(const char* item) {
  names_t* name = malloc(sizeof(names_t));
  if (name) {
    char* itemname = strdup(item);
    if (itemname) {
      name->name = itemname;
      name->next = names;
      names = name;
    } else {
      perror(item);
      free(name);
    }
  } else
    perror(item);
}

static void read_from_file(const char *filename) {
  FILE *in;
  if (!filename || !strcmp(filename, "-")) {
    clearerr(stdin);
    in = stdin;
  } else {
    in = fopen(filename, "r");
    if (!in) {
      perror(filename);
      return;
    }
  }

  char *line = malloc(PATH_MAX);
  if (!line) {
    perror(filename);
    if (in != stdin)
      fclose(in);
    return;
  }

  while (fgets(line, sizeof(line), in))
    append_to_names(trim(line));
  if (ferror(in))
    perror(filename);
  if (in != stdin)
    fclose(in);
  free(line);
}

/*
 * If the file stream is associated with a regular file, lock the file
 * in order coordinate writes to a common file from multiple mtr
 * instances. This is useful if, for example, multiple mtr instances
 * try to append results to a common file.
 */

static void lock(FILE *f) {
    int fd;
    struct stat buf;
    static struct flock lock;

    assert(f);

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_END;
    lock.l_len = 0;
    lock.l_pid = mypid;

    fd = fileno(f);
    if (!fstat(fd, &buf) && S_ISREG(buf.st_mode))
      if (fcntl(fd, F_SETLKW, &lock) == -1)
        perror("fcntl()");
}

/*
 * If the file stream is associated with a regular file, unlock the
 * file (which presumably has previously been locked).
 */

static void unlock(FILE *f) {
    int fd;
    struct stat buf;
    static struct flock lock;

    assert(f);

    lock.l_type = F_UNLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_END;
    lock.l_len = 0;
    lock.l_pid = mypid;

    fd = fileno(f);
    if (!fstat(fd, &buf) && S_ISREG(buf.st_mode))
      if (fcntl(fd, F_SETLKW, &lock) == -1)
        perror("fcntl()");
}

static struct option long_options[] = {
  { "address",    1, 0, 'a' },
  { "show-ips",   0, 0, 'b' },
  { "bitpattern", 1, 0, 'B' },   // overload b>255, ->rand(0,255)
  { "report-cycles", 1, 0, 'c' },
#if defined(CURSES) || defined(GRAPHCAIRO)
  { "display",    1, 0, 'd' },
#endif
  { "mpls",       0, 0, 'e' },
  { "help",       0, 0, 'h' },
  { "first-ttl",  1, 0, 'f' },   // -f and -m are borrowed from traceroute
  { "filename",   1, 0, 'F' },
#ifdef GRAPHCAIRO
  { "graphcairo", 1, 0, 'G' },
#endif
  { "interval",   1, 0, 'i' },
#ifdef OUTPUT_FORMAT
  { "output",     1, 0, 'l' },
#endif
  { "max-ttl",    1, 0, 'm' },
  { "no-dns",     0, 0, 'n' },
  { "order",      1, 0, 'o' },   // fields to display and their order
#ifdef SPLITMODE
  { "split",      0, 0, 'p' },
#endif
  { "port",       1, 0, 'P' },  // target port number for TCP
  { "tos",        1, 0, 'Q' },  // typeof service (0,255)
  { "report",     0, 0, 'r' },
  { "psize",      1, 0, 's' },  // changed 'p' to 's' to match ping option, overload psize<0, ->rand(min,max)
  { "tcp",        0, 0, 'T' },  // TCP (default is ICMP)
  { "udp",        0, 0, 'u' },  // UDP (default is ICMP)
  { "version",    0, 0, 'v' },
  { "report-wide", 0, 0, 'w' },
  { "cache",      1, 0, 'x' },  // enable cache with timeout in seconds (0 means default 60sec)
#ifdef IPINFO
  { "ipinfo",     1, 0, 'y' },
  { "aslookup",   0, 0, 'z' },
#endif
  { "timeout",    1, 0, 'Z' },  // timeout for TCP sockets
  { "inet",       0, 0, '4' },  // use IPv4
#ifdef ENABLE_IPV6
  { "inet6",      0, 0, '6' },  // use IPv6
#endif
  { 0, 0, 0, 0 }
};

static char *short_options;

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

static char *get_opt_desc(char opt) {
  switch (opt) {
    case 'm':
    case 'f':
    case 'B':
    case 'Q':
    case 'P': return "NUMBER";
    case 'i':
    case 'x':
    case 'Z': return "SECONDS";
    case 'a': return "IP.ADD.RE.SS";
    case 'c': return "COUNT";
    case 'd': return "MODE";
    case 's': return "BYTES";
    case 'o': return "FIELDS";
    case 'F': return "FILE";
#ifdef OUTPUT_FORMAT
    case 'l': return trim(""
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
);
#endif
#ifdef IPINFO
    case 'y': return "ORIGIN,FIELDS";
#endif
#ifdef GRAPHCAIRO
    case 'G': return "type,period,enable_legend,enable_multipath,enable_jitter";
#endif
  }
  return NULL;
}

static void usage(char *name) {
  printf("Usage: %s [-", name);
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
//    if (!c) // LATER: do it in more common way
//      if (!strncmp(long_options[i].name, SOME_LONG_OPTION, sizeof(SOME_LOG_OPTION)))
//        c = 'i'; // seconds
    char *desc = long_options[i].has_arg ? get_opt_desc(c) : NULL;
    if (desc)
      printf(" %s", desc);
    printf("]\n");
  }
}

static void say_limit(const int v0, const int v1, int v, const char *it, const int res) {
  fprintf(stderr, "WARN: '%s' is out of range %d..%d: %d -> %d\n", it, v0, v1, v, res);
}

static int limit_int(const int v0, const int v1, const int v, const char *it) {
  if (v < v0) {
    say_limit(v0, v1, v, it, v0);
    return v0;
  }
  if (v > v1) {
    say_limit(v0, v1, v, it, v1);
    return v1;
  }
  return v;
}
 
static void parse_arg(int argc, char **argv) {
  while (1) {
    int opt = my_getopt_long(argc, argv, NULL);
    if (opt == -1)
      break;

    switch (opt) {
    case '?':
      usage(argv[0]);
      exit(-1);
    case 'h':
      usage(argv[0]);
      exit(0);
    case 'v':
      printf ("%s-%s\n", argv[0], MTR_VERSION);
      exit(0);
    case 'r':
      display_mode = DisplayReport;
      break;
    case 'w':
      report_wide = true;
      display_mode = DisplayReport;
      break;
#ifdef SPLITMODE
    case 'p':
      display_mode = DisplaySplit;
      break;
#endif
#ifdef OUTPUT_FORMAT
    case 'l':
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
          exit(-1);
      }
      break;
#endif
#if defined(CURSES) || defined(GRAPHCAIRO)
    case 'd':
      curses_mode = ((atoi(optarg)) & ~8) % curses_mode_max;
      color_mode = ((atoi(optarg)) & 8) ? 1 : 0;
      audible_bell = ((atoi(optarg)) & 16) ? 1 : 0;
      visible_bell = ((atoi(optarg)) & 32) ? 1 : 0;
      target_bell_only = ((atoi(optarg)) & 64) ? 1 : 0;
      break;
#endif
    case 'c':
      max_ping = atoi(optarg);
      alter_ping = true;
      break;
    case 's':
      cpacketsize = atoi(optarg);
      break;
    case 'a':
      iface_addr = optarg;
      break;
    case 'e':
      enable_mpls = true;
      break;
#ifdef GRAPHCAIRO
    case 'G':
      gc_parsearg(optarg);
      display_mode = DisplayGraphCairo;
      break;
#endif
    case 'n':
      enable_dns = false;
      break;
    case 'i':
      wait_time = atof(optarg);
      if (wait_time <= 0) {
        fprintf(stderr, "Wait time must be positive\n");
        exit(1);
      }
      if (getuid() && (wait_time < 1)) {
        fprintf(stderr, "Non-root users cannot request an interval < 1.0 seconds\n");
        exit(1);
      }
      break;
    case 'f':
      if (optarg[0] == 'a') {
        endpoint_mode = true;
        break;
      }
      fstTTL = limit_int(1, maxTTL, atoi(optarg), "first ttl");
      break;
    case 'F':
      read_from_file(optarg);
      break;
    case 'm':
      maxTTL = limit_int(1, ((MAXHOST - 1) > maxTTL) ? maxTTL : (MAXHOST - 1), atoi(optarg), "maximum ttl");
      break;
    case 'o':
      /* Check option before passing it on to fld_active. */
      if (strlen(optarg) >= sizeof(fld_active)) {
        fprintf(stderr, "Too many fields (max=%zd): %s\n", sizeof(fld_active) - 1, optarg);
        exit(1);
      }
      for (int i = 0; optarg[i]; i++) {
        if(!strchr(fld_avail, optarg[i])) {
          fprintf(stderr, "Unknown field identifier: %c\n", optarg[i]);
          exit(1);
        }
      }
      set_fld_active(optarg);
      break;
    case 'B':
      bitpattern = atoi(optarg);
      if (bitpattern > 255)
        bitpattern = -1;
      break;
    case 'Q':
      tos = atoi(optarg);
      if (tos > 255 || tos < 0)	// error message, should do more checking for valid values
        tos = 0;
      break;
    case 'u':
      if (mtrtype != IPPROTO_ICMP) {
        fprintf(stderr, "-u and -T are mutually exclusive.\n");
        exit(EXIT_FAILURE);
      }
      mtrtype = IPPROTO_UDP;
      break;
    case 'T':
      if (mtrtype != IPPROTO_ICMP) {
        fprintf(stderr, "-u and -T are mutually exclusive.\n");
        exit(EXIT_FAILURE);
      }
      if (net_tcp_init())
        mtrtype = IPPROTO_TCP;
      else {
        fprintf(stderr, "Switch to TCP mode failed.\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'b':
      show_ips = true;
      break;
    case 'P':
      remoteport = atoi(optarg);
      if (remoteport > 65535 || remoteport < 1) {
        fprintf(stderr, "Illegal port number: %d\n", remoteport);
        exit(EXIT_FAILURE);
      }
      break;
    case 'x':
      cache_mode = true;
      cache_timeout = atoi(optarg);
	  if (cache_timeout < 0) {
        fprintf(stderr, "Cache timeout must be positive: %d\n", cache_timeout);
        exit(EXIT_FAILURE);
      } else if (cache_timeout == 0)
        cache_timeout = CACHE_TIMEOUT;  // default 60 seconds
      break;
#ifdef IPINFO
    case 'y':
      ii_parsearg(optarg);
      break;
    case 'z':
      ii_parsearg(ASLOOKUP_DEFAULT);
      break;
#endif
    case 'Z':
      tcp_timeout = atoi(optarg);
      tcp_timeout *= 1000000;
      break;
    case '4':
      net_init(0);
      break;
#ifdef ENABLE_IPV6
    case '6':
      net_init(1);
      break;
#endif
    }
  }

  static int sz;
  for (int i = 1; i < argc; i++)
    sz += snprintf(mtr_args + sz, sizeof(mtr_args) - sz, " %s", argv[i]);

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

  if (optind > argc - 1)
    return;
}


static void parse_mtr_options(char *string) {
  int argc;
  char *argv[128];

  if (!string)
    return;

  argv[0] = PACKAGE_NAME;
  argc = 1;
  char *p = string;
  while (*p) {
    if (argc == sizeof(argv) / sizeof(argv[0]) - 1) {
      fprintf(stderr, "WARN: extra arguments ignored: %s\n", p);
      break;
    }
    while (*p && isspace((int)*p))
      p++;

    if (*p == '"' || *p == '\'') {
      int delim = *p++;
      char *q = strdup(p);
      argv[argc++] = q;
      while (*p && *p != delim) {
        if (*p == '\\')
          p++;
        *q++ = *p++;
      }
      *q = 0;
    } else {
      argv[argc++] = p;
      while (*p && !isspace((int)*p))
        p++;
    }

    if (*p == 0)
      break;
    *p++ = 0;
  }

  argv[argc] = NULL;
  parse_arg(argc, argv);
  optind = 0;
}

#define IDNA_RESOLV(func) { \
  rc = func(dsthost, &z_hostname, 0); \
  if (rc == IDNA_SUCCESS) \
    rc = getaddrinfo(z_hostname, NULL, &hints, &res); \
  else \
    rc_msg = idna_strerror(rc); \
  if (z_hostname) \
    free(z_hostname); \
}

static int set_hostent(struct addrinfo *res) {
    struct addrinfo *ai;
    for (ai = res; ai; ai = ai->ai_next)
      if (af == ai->ai_family)	// use only the desired AF
        break;
    if (af != ai->ai_family) {	// not found
      fprintf(stderr, "Desired address family not found: %d\n", af);
      return 0;	// unsuccess
    }

    char* alptr[2] = { NULL, NULL };
    if (af == AF_INET)
      alptr[0] = (void*) &(((struct sockaddr_in *)ai->ai_addr)->sin_addr);
#ifdef ENABLE_IPV6
    else if (af == AF_INET6)
      alptr[0] = (void*) &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr);
#endif
    else {
      fprintf(stderr, "Desired address family not found: %d\n", af);
      return 0;	// unsuccess
    }

    static struct hostent entry;
    memset(&entry, 0, sizeof(entry));
    entry.h_name = ai->ai_canonname;
    entry.h_aliases = NULL;
    entry.h_addrtype = ai->ai_family;
    entry.h_length = ai->ai_addrlen;
    entry.h_addr_list = alptr;

    if (net_open(&entry)) {
      perror("Unable to start net module");
      return 0;	// unsuccess
    }
    if (net_set_interfaceaddress(iface_addr)) {
      perror("Couldn't set interface address");
      return 0;	// unsuccess
    }
    return 1;	// success
}


int main(int argc, char **argv) {
  net_init(0);		// Use IPv4 by default

  /*  Get the raw sockets first thing, so we can drop to user euid immediately  */
  if (net_preopen()) {
    perror("Unable to get raw sockets");
    exit(EXIT_FAILURE);
  }

  /*  Now drop to user permissions  */
  if (setgid(getgid()) || setuid(getuid())) {
    perror("Unable to drop permissions");
    exit(1);
  }

  /*  Double check, just in case  */
  if ((geteuid() != getuid()) || (getegid() != getgid())) {
    perror("Unable to drop permissions");
    exit(1);
  }

  mypid = getpid();

  /* reset the random seed */
  srand(mypid);

  display_detect(&argc, &argv);
#if defined(CURSES) || defined(GRAPHCAIRO)
  curses_mode = 0;
#endif

  /* The field options are now in a static array all together,
     but that requires a run-time initialization. */
  memset(fld_index, -1, sizeof(fld_index));
  for (int i = 0; (data_fields[i].key) && (i < sizeof(fld_avail)); i++) {
    fld_avail[i] = data_fields[i].key;
    fld_index[data_fields[i].key] = i;
  }

#ifdef UNICODE
  bool dm_histogram = false;
#ifdef HAVE_LOCALE_H
  char *lc_ctype = setlocale(LC_CTYPE, NULL);
  setlocale(LC_CTYPE, "");
#ifdef HAVE_LANGINFO_H
  if (strcasecmp("UTF-8", nl_langinfo(CODESET)) == 0) {
    if (iswprint(L'▁'))
      dm_histogram = true;
    else
      perror("Unicode block elements are not printable");
  }
#endif
  if (dm_histogram)
    curses_mode_max++;
  else
    setlocale(LC_CTYPE, lc_ctype);
#endif
#endif

  set_fld_active(FLD_ACTIVE_DEFAULT);
  parse_mtr_options(getenv("MTR_OPTIONS"));
  parse_arg(argc, argv);

  while (optind < argc) {
    char* name = argv[optind++];
    append_to_names(name);
  }

  if (!names) {
    usage(argv[0]);
    exit(0);
  }

  /* Now that we know mtrtype we can select which socket to use */
  if (net_selectsocket() != 0) {
    perror("Couldn't determine raw socket type");
    exit(EXIT_FAILURE);
  }

  dns_open();
#ifdef IPINFO
  ii_open();
#endif
  if (gethostname(srchost, sizeof(srchost)))
    strncpy(srchost, "UNKNOWN", sizeof(srchost));
  display_start();

  for (names_t* n = names; n; n = n->next) {
    static bool notfirst;
    dsthost = n->name;

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_DGRAM;
    int rc = getaddrinfo(dsthost, NULL, &hints, &res);
    const char *rc_msg = NULL;
#if defined(HAVE_LIBIDN) || defined(HAVE_LIBIDN2)
    if (rc) {
      char *z_hostname = NULL;
      IDNA_RESOLV(IDN_TO_ASCII_LZ);
      if (rc)
        IDNA_RESOLV(IDN_TO_ASCII_8Z);
    }
#endif
    if (rc) {
      if (rc == EAI_SYSTEM)
        perror(dsthost);
      else
        fprintf(stderr, "Failed to resolve \"%s\": %s\n", dsthost, rc_msg ? rc_msg : gai_strerror(rc));
    } else {
      if (set_hostent(res)) {
        lock(stdout);
        display_open();
        display_loop();
        net_end_transit();
        display_close(notfirst);
        unlock(stdout);
      }
      freeaddrinfo(res);
    }
    notfirst = true;
  }

  display_finish();
#ifdef IPINFO
  ii_close();
#endif
  dns_close();
  net_close();
  return 0;
}

