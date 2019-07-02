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

#include "config.h"

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef HAVE_LIBIDN
#include <idna.h>
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

pid_t mypid;
int   DisplayMode;
#if defined(CURSES) || defined(GRAPHCAIRO)
int   display_mode_max = 3;
#endif
int   Interactive = 1;
int   MaxPing = 10;
int   ForceMaxPing;
float WaitTime = 1.0;
char *Hostname = NULL;
char *InterfaceAddress = NULL;
char  LocalHostname[128];
char  mtr_args[1024];	// posix/susvn: 4096+
unsigned iargs;	// args passed interactively
int   cpacketsize = 64;          /* default packet size */
int   bitpattern;
int   tos;
int   reportwide;
int   mtrtype = IPPROTO_ICMP;    /* Use ICMP as default packet type */
int   fstTTL = 1;                /* default start at first hop */
int   endpoint_mode;             /* set by -fz option */
int   remoteport = 80;           /* for TCP tracing */
int   timeout = 10 * 1000000;    /* for TCP tracing */

/* default display field(defined by key in net.h) and order */
unsigned char fld_active[2*MAXFLD];
unsigned char fld_active_save[2*MAXFLD];
int           fld_index[256];
char          available_options[MAXFLD];


struct fields data_fields[MAXFLD] = {
  /* key, Remark, Header, Format, Width */
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

typedef struct names {
  char*                 name;
  struct names*         next;
} names_t;
static names_t *names = NULL;

char* trim(char *s) {
  char *p = s;
  int l = strlen(p);
  while (isspace((int)p[l-1]) && l)
    p[--l] = 0;
  while (isspace((int)*p))
    p++;
  return p;
}

word str2hash(const char* s) {
  word h = 0;
  int c;
  while ((c = *s++))
    h = ((h << 5) + h) ^ c; // h * 33 ^ c
  return h;
}

void set_fld_active(const char *s) {
  static char s_copy[2*MAXFLD];
  strncpy(s_copy, s, sizeof(s_copy));
  memset(fld_active_save, 0, sizeof(fld_active_save));
  strncpy((char*)fld_active_save, (char*)fld_active, sizeof(fld_active_save));
  memset(fld_active, 0, sizeof(fld_active));
  strncpy((char*)fld_active, s_copy, sizeof(fld_active));
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

void init_fld_options (void) {
  memset(fld_index, -1, sizeof(fld_index));

  int i;
  for (i = 0; data_fields[i].key; i++) {
    available_options[i] = data_fields[i].key;
    fld_index[data_fields[i].key] = i;
  }
  available_options[i] = 0;
}

static struct option long_options[] = {
  { "address",	1, 0, 'a' },
  { "show-ips",	0, 0, 'b' },
  { "bitpattern",	1, 0, 'B' },	/* overload b>255, ->rand(0,255) */
  { "report-cycles",	1, 0, 'c' },
#if defined(CURSES) || defined(GRAPHCAIRO)
  { "display",	1, 0, 'd' },
#endif
  { "mpls",	0, 0, 'e' },
  { "first-ttl",	1, 0, 'f' },	/* -f & -m are borrowed from traceroute */
  { "filename",	1, 0, 'F' },
#ifdef GRAPHCAIRO
  { "graphcairo",	1, 0, 'G' },
#endif
  { "interval",	1, 0, 'i' },
#if defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_RAW) || defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_XML)
  { "output",	1, 0, 'l' },
#endif
  { "max-ttl",	1, 0, 'm' },
  { "no-dns",	0, 0, 'n' },
  { "order",	1, 0, 'o' },	/* fileds to display & their order */
#ifdef SPLITMODE
  { "split",	0, 0, 'p' },
#endif
  { "port",	1, 0, 'P' },	/* target port number for TCP */
  { "tos",	1, 0, 'Q' },	/* typeof service (0,255) */
  { "report",	0, 0, 'r' },
  { "psize",	1, 0, 's' },	/* changed 'p' to 's' to match ping option, overload psize<0, ->rand(min,max) */
  { "tcp",	0, 0, 'T' },	/* TCP (default is ICMP) */
  { "udp",	0, 0, 'u' },	/* UDP (default is ICMP) */
  { "version",	0, 0, 'v' },
  { "report-wide",	0, 0, 'w' },
#ifdef IPINFO
  { "ipinfo",	1, 0, 'y' },
  { "aslookup",	0, 0, 'z' },
#endif
  { "timeout",	1, 0, 'Z' },	/* timeout for TCP sockets */
  { "inet",	0, 0, '4' },	/* use IPv4 */
#ifdef ENABLE_IPV6
  { "inet6",	0, 0, '6' },	/* use IPv6 */
#endif
  { 0, 0, 0, 0 }
};

static char *short_options;

int my_getopt_long(int argc, char *argv[]) {
  if (!short_options) {
    short_options = malloc((sizeof(long_options) / sizeof(long_options[0])) * 2 + 1);
    if (!short_options)
      return -1; // Trouble!

    char *p = short_options;
    int i;
    for (i = 0; long_options[i].name; i++) {
      *p++ = (char)long_options[i].val;
      if (long_options[i].has_arg)
        *p++ = ':';
    }
    *p++ = '\0';
  }
  return getopt_long(argc, argv, short_options, long_options, NULL);
}

char *get_opt_desc(char opt) {
  switch (opt) {
    case 'm':
    case 'f':
    case 'B':
    case 'Q':
    case 'P': return "NUMBER";
    case 'i':
    case 'Z': return "SECONDS";
    case 'a': return "IP.ADD.RE.SS";
    case 'c': return "COUNT";
    case 'd': return "MODE";
    case 's': return "BYTES";
    case 'o': return "FIELDS";
    case 'F': return "FILE";
#if defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_RAW) || defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_XML)
    case 'l': return ""
#ifdef OUTPUT_FORMAT_CSV
" CSV"
#endif
#ifdef OUTPUT_FORMAT_RAW
" RAW"
#endif
#ifdef OUTPUT_FORMAT_TXT
" TXT"
#endif
#ifdef OUTPUT_FORMAT_XML
" XML"
#endif
;
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

void usage(char *name) {
  printf("Usage: %s [-", name);
  int i, l = strlen(short_options);
  for (i = 0; i < l; i++)
    if (short_options[i] != ':')
      putchar(short_options[i]);
  printf("] HOSTNAME ...\n");
  for (i = 0; long_options[i].name; i++) {
    printf("\t[-%c|--%s", (char)long_options[i].val, long_options[i].name);
    if (long_options[i].has_arg) {
      char *desc = get_opt_desc((char)long_options[i].val);
      if (desc)
        printf(" %s", desc);
    }
    printf("]\n");
  }
}

void parse_arg(int argc, char **argv) {
  int opt;
  int i;
  opt = 0;
  while(1) {
    /* added f:m:o: byMin */
    opt = my_getopt_long(argc, argv);
    if(opt == -1)
      break;

    switch(opt) {
    case '?':
      usage(argv[0]);
      exit(-1);
    case 'v':
      printf ("%s-%s\n", argv[0], MTR_VERSION);
      exit(0);
    case 'r':
      DisplayMode = DisplayReport;
      break;
    case 'w':
      reportwide = 1;
      DisplayMode = DisplayReport;
      break;
#ifdef SPLITMODE
    case 'p':
      DisplayMode = DisplaySplit;
      break;
#endif
#if defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_RAW) || defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_XML)
    case 'l':
      switch (tolower((int)optarg[0])) {
#ifdef OUTPUT_FORMAT_CSV
        case 'c':
          DisplayMode = DisplayCSV;
          break;
#endif
#ifdef OUTPUT_FORMAT_RAW
        case 'r':
          DisplayMode = DisplayRaw;
          enable_raw = 1;
          break;
#endif
#ifdef OUTPUT_FORMAT_TXT
        case 't':
          DisplayMode = DisplayTXT;
          break;
#endif
#ifdef OUTPUT_FORMAT_XML
        case 'x':
          DisplayMode = DisplayXML;
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
      display_mode = ((atoi(optarg)) & ~8) % display_mode_max;
      color_mode = ((atoi(optarg)) & 8) ? 1 : 0;
      break;
#endif
    case 'c':
      MaxPing = atoi (optarg);
      ForceMaxPing = 1;
      break;
    case 's':
      cpacketsize = atoi (optarg);
      break;
    case 'a':
      InterfaceAddress = optarg;
      break;
    case 'e':
      enablempls = 1;
      break;
    case 'n':
      enable_dns = 0;
      break;
    case 'i':
      WaitTime = atof (optarg);
      if (WaitTime <= 0.0) {
        fprintf(stderr, "Wait time must be positive\n");
        exit(1);
      }
      if (getuid() != 0 && WaitTime < 1.0) {
        fprintf(stderr, "Non-root users cannot request an interval < 1.0 seconds\n");
        exit(1);
      }
      break;
    case 'f':
      if (optarg[0] == 'z') {
        endpoint_mode = 1;
        break;
      }
      fstTTL = atoi (optarg);
      if (fstTTL > maxTTL)
        fstTTL = maxTTL;
      if (fstTTL < 1)	/* prevent 0 hop */
        fstTTL = 1;
      break;
    case 'F':
      read_from_file(optarg);
      break;
    case 'm':
      maxTTL = atoi (optarg);
      if (maxTTL > (MaxHost - 1))
        maxTTL = MaxHost-1;
      if (maxTTL < 1)	/* prevent 0 hop */
        maxTTL = 1;
      if (fstTTL > maxTTL) /* don't know the pos of -m or -f */
        fstTTL = maxTTL;
      break;
    case 'o':
      /* Check option before passing it on to fld_active. */
      if (strlen (optarg) > MAXFLD) {
        fprintf(stderr, "Too many fields: %s\n", optarg);
        exit (1);
      }
      for (i=0; optarg[i]; i++) {
        if(!strchr (available_options, optarg[i])) {
          fprintf (stderr, "Unknown field identifier: %c\n", optarg[i]);
          exit (1);
        }
      }
      set_fld_active(optarg);
      break;
    case 'B':
      bitpattern = atoi (optarg);
      if (bitpattern > 255)
        bitpattern = -1;
      break;
    case 'Q':
      tos = atoi (optarg);
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
      show_ips = 1;
      break;
    case 'P':
      remoteport = atoi(optarg);
      if (remoteport > 65535 || remoteport < 1) {
        fprintf(stderr, "Illegal port number.\n");
        exit(EXIT_FAILURE);
      }
      break;
    case 'Z':
      timeout = atoi(optarg);
      timeout *= 1000000;
      break;
    case '4':
      net_init(0);
      break;
#ifdef ENABLE_IPV6
    case '6':
      net_init(1);
      break;
#endif
#ifdef IPINFO
    case 'y':
      ii_parsearg(optarg);
      break;
    case 'z':
      ii_parsearg(ASLOOKUP_DEFAULT);
      break;
#endif
#ifdef GRAPHCAIRO
    case 'G':
      gc_parsearg(optarg);
      DisplayMode = DisplayGraphCairo;
      break;
#endif
    }
  }

  static int sz;
  for (i = 1; i < argc; i++)
    sz += snprintf(mtr_args + sz, sizeof(mtr_args) - sz, " %s", argv[i]);

  switch (DisplayMode) {
    case DisplayReport:
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV:
#endif
#ifdef OUTPUT_FORMAT_RAW
    case DisplayRaw:
#endif
#ifdef OUTPUT_FORMAT_TXT
    case DisplayTXT:
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
      Interactive = 0;
  }

  if (optind > argc - 1)
    return;
}


void parse_mtr_options(char *string) {
  int argc;
  char *argv[128];

  if (!string)
    return;

  argv[0] = PACKAGE_NAME;
  argc = 1;
  char *p = string;
  while (*p) {
    if (argc == sizeof(argv) / sizeof(argv[0]) - 1) {
      fprintf(stderr, "Warning: extra arguments ignored: %s", p);
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

int set_hostent(struct addrinfo *res) {
    struct addrinfo *ai;
    for (ai = res; ai; ai = ai->ai_next)
      if (af == ai->ai_family)	// use only the desired AF
        break;
    if (af != ai->ai_family)	// not found
      return 0;	// unsuccess

    char* alptr[2] = { NULL, NULL };
    if (af == AF_INET)
      alptr[0] = (void*) &(((struct sockaddr_in *)ai->ai_addr)->sin_addr);
#ifdef ENABLE_IPV6
    else if (af == AF_INET6)
      alptr[0] = (void*) &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr);
#endif
    else
      return 0;	// unsuccess

    static struct hostent host;
    memset(&host, 0, sizeof(host));
    host.h_name = ai->ai_canonname;
    host.h_aliases = NULL;
    host.h_addrtype = ai->ai_family;
    host.h_length = ai->ai_addrlen;
    host.h_addr_list = alptr;

    if (net_open(&host)) {
      perror("Unable to start net module");
      return 0;	// unsuccess
	}
    if (net_set_interfaceaddress(InterfaceAddress)) {
      perror("Couldn't set interface address");
      return 0;	// unsuccess
    }
    return 1;	// success
}


int main(int argc, char **argv) {
  net_init(0);		// Use IPv4 by default
  enable_dns = 1;	// Use DNS
  maxTTL = 30;		// Is it enough?

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
  display_mode = 0;
#endif

  /* The field options are now in a static array all together,
     but that requires a run-time initialization. */
  init_fld_options ();

#ifdef UNICODE
  int dm_histogram = 0;
  char *lc_ctype = setlocale(LC_CTYPE, NULL);
  setlocale(LC_CTYPE, "");
  if (strcasecmp("UTF-8", nl_langinfo(CODESET)) == 0) {
    if (iswprint(L'▁'))
      dm_histogram = 1;
    else
      perror("Unicode block elements are not printable");
  }
  if (dm_histogram)
    display_mode_max++;
  else
    setlocale(LC_CTYPE, lc_ctype);
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

  time_t now = time(NULL);
  for (names_t *n = names; n; n = n->next) {
    Hostname = n->name;
    if (gethostname(LocalHostname, sizeof(LocalHostname)))
      strcpy(LocalHostname, "UNKNOWNHOST");

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = af;
    hints.ai_socktype = SOCK_DGRAM;
    int error = getaddrinfo(Hostname, NULL, &hints, &res);
#ifdef HAVE_LIBIDN
    if (error) {
      char *z_hostname;
      if (idna_to_ascii_lz(Hostname, &z_hostname, 0) == IDNA_SUCCESS)
        error = getaddrinfo(z_hostname, NULL, &hints, &res);
      if (error)
        if (idna_to_ascii_8z(Hostname, &z_hostname, 0) == IDNA_SUCCESS)
          error = getaddrinfo(z_hostname, NULL, &hints, &res);
    } else
#endif
    {
      if (error) {
        if (error == EAI_SYSTEM)
          perror(Hostname);
        else
          fprintf(stderr, "Failed to resolve \"%s\": %s\n", Hostname, gai_strerror(error));
      } else if (set_hostent(res)) {
        lock(stdout);
        display_open();
        dns_open();
        display_loop();
        net_end_transit();
        display_close(now);
        unlock(stdout);
      }
    }
    freeaddrinfo(res);
  }

  net_close();
  return 0;
}
