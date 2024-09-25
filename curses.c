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

#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <limits.h>
#include <time.h>

#include "mtr-curses.h"
#include "config.h"

#ifdef WITH_UNICODE
#ifndef _XOPEN_SOURCE_EXTENDED
#define _XOPEN_SOURCE_EXTENDED
#endif
#ifdef HAVE_WCHAR_H
#  include <wchar.h>
#endif
#ifdef __NetBSD__
#define CCHAR_attr attributes
#define CCHAR_chars vals
/*
#elif defined(OPENSOLARIS_CURSES)
#define CCHAR_attr _at
#define CCHAR_chars _wc
*/
#else
#define CCHAR_attr attr
#define CCHAR_chars chars
#endif
#endif // WITH_UNICODE

#if   defined(HAVE_NCURSESW_NCURSES_H)
#  include <ncursesw/ncurses.h>
#elif defined(HAVE_NCURSESW_CURSES_H)
#  include <ncursesw/curses.h>
#elif defined(HAVE_NCURSES_NCURSES_H)
#  include <ncurses/ncurses.h>
#elif defined(HAVE_NCURSES_CURSES_H)
#  include <ncurses/curses.h>
#elif defined(HAVE_NCURSES_H)
#  include <ncurses.h>
#elif defined(HAVE_CURSES_H)
#  include <curses.h>
#else
#  error No curses header file available
#endif

#include "aux.h"
#include "display.h"
#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

const char CMODE_HINTS[] =
"Commands:\n"
"  b <int>    set bit pattern in range 0..255, or random (<0)\n"
"  c <int>    set number of cycles to run, or unlimit (<1)\n"
"  d          switch display mode\n"
#ifdef WITH_MPLS
"  e          toggle MPLS info\n"
#endif
"  f <int>    set first TTL (default 1)\n"
"  i <int>    set interval in seconds (default 1)\n"
"  j          toggle lattency/jitter stats (default latency)\n"
"  m <int>    set max TTL (default 30)\n"
#ifdef ENABLE_DNS
"  n          toggle DNS\n"
#endif
"  o <str>    set fields to display (default 'LRS N BAWV')\n"
"  p|<space>  pause and resume\n"
"  q          quit\n"
"  Q <int>    set ToS/QoS\n"
"  r          reset statistics\n"
"  s <int>    set packet size (default 64), or random (<0)\n"
"  t          toggle TCP pings\n"
"  u          toggle UDP pings\n"
"  x          toggle cache mode\n"
#ifdef WITH_IPINFO
"  y          switch IP info\n"
"  z          toggle ASN lookup\n"
#endif
"  +-         scroll up/down\n"
"  hH?        this help page\n"
"\n"
"Press any key to resume ...";

static int __unused_int;
static char entered[MAXFLD + 1]; // enough?
static char mc_title[256]; // basename-version arguments destination

static int enter_smth(int y) {
  move(2, y);
  memset(entered, 0, sizeof(entered));
  int curs = curs_set(1);
  refresh();
  for (int i = 0, c; ((c = getch()) != '\n') && (i < MAXFLD);) {
    addch(c | A_BOLD);
    refresh();
    entered[i++] = c;
  }
  if (curs != ERR) curs_set(curs);
  return strnlen(entered, MAXFLD);
}

static void enter_stat_fields(void) {
  char fields[MAXFLD + 1];
  memset(fields, 0, sizeof(fields));
  int curs = curs_set(1);
  for (int i = 0, c; ((c = getch()) != '\n') && (i < MAXFLD);) {
    int j = 0;
    for (; j < statf_max; j++) {
      if (c == statf[j].key) { // only statf[].key allowed
        addch(c | A_BOLD);
        refresh();
        fields[i++] = c;
        break;
      }
    }
    if (j >= statf_max) // illegal character
      putchar('\a'); // beep
  }
  if (strnlen(fields, MAXFLD))
    set_fld_active(fields);
  if (curs != ERR) curs_set(curs);
}

int mc_keyaction(void) {
  int c = getch();

  switch (c) {
    case '+': return ActionScrollDown;
    case '-': return ActionScrollUp;
    case '?':
    case 'h':
      erase();
      mvprintw(2, 0, CMODE_HINTS);
      getch();
      return ActionNone;
    case 'b':
      mvprintw(2, 0, "Ping Bit Pattern: %d\n", cbitpattern);
      mvprintw(3, 0, "Pattern Range: 0-255, -1 random.\n");
      if (enter_smth(18))
        cbitpattern = limit_int(-1, 255, atoi((char*)entered), "Bit Pattern");
      return ActionNone;
    case 'c':
      mvprintw(2, 0, "Number (unlimit < 1) of cycles: %ld\n\n", max_ping);
      if (enter_smth(32))
        max_ping = atol((char*)entered);
      return ActionNone;
    case 'd': return ActionDisplay;
#ifdef WITH_MPLS
    case 'e': return ActionMPLS;
#endif
    case 'f':
      mvprintw(2, 0, "First TTL: %d\n\n", fstTTL);
      if (enter_smth(11))
        fstTTL = limit_int(1, maxTTL, atoi((char*)entered), "First TTL");
      return ActionNone;
    case 'i':
      mvprintw(2, 0, "Interval: %0.0f\n\n", wait_time);
      if (enter_smth(11)) {
        double f = atof((char*)entered);
        if (f >= 1)
          wait_time = f;
        else if ((f > 0) && (f < 1) && getuid())
          wait_time = f;
        else
          WARNX_("Wrong Interval: %s", (char*)entered);
      }
      return ActionNone;
    case 'j':
      TGLBIT(run_args, RA_JITTER);	// latency OR jitter
      onoff_jitter();
      return ActionNone;
    case 'm':
      mvprintw(2, 0, "Max TTL: %d\n\n", maxTTL);
      if (enter_smth(9))
        maxTTL = limit_int(1, ((MAXHOST - 1) > maxTTL) ? maxTTL : (MAXHOST - 1), atoi((char*)entered), "Max TTL");
      return ActionNone;
#ifdef ENABLE_DNS
    case 'n': return ActionDNS;
#endif
    case 'o':  // fields to display and their ordering
      mvprintw(2, 0, "Fields: %s\n\n", fld_active);
      for (int i = 0; i < statf_max; i++)
        if (statf[i].hint)
          printw("  %s\n", statf[i].hint);
      addch('\n');
      move(2, 8); // length of "Fields: "
      refresh();
      enter_stat_fields();
      return ActionNone;
    case ' ':
    case 'p': return ActionPauseResume;
    case  3 : // ^C
    case 'q': return ActionQuit;
    case 'Q':
      mvprintw(2, 0, "ToS (Type of Service): %d\n", tos);
      mvprintw(3, 0, "Bits: 1st lowcost, 2nd reliability, 3rd throughput, 4th lowdelay\n");
      if (enter_smth(23))
        tos = limit_int(0, 255, atoi((char*)entered), "Type of Service (ToS)");
      return ActionNone;
    case 'r': return ActionReset;
    case 's':
      mvprintw(2, 0, "Change Packet Size: %d\n", cpacketsize);
      mvprintw(3, 0, "Size Range: %d-%d, < 0:random.\n", MINPACKET, MAXPACKET);
      if (enter_smth(20)) {
        int s_val = atoi((char*)entered);
        cpacketsize = limit_int(MINPACKET, MAXPACKET, abs(s_val), "Packet size");
        if (s_val < 0)
          cpacketsize = -cpacketsize;
      }
      return ActionNone;
    case 't': return ActionTCP;
    case 'u': return ActionUDP;
    case 'x': return ActionCache;
#ifdef WITH_IPINFO
    case 'y': return ActionII;
    case 'z': return ActionAS;
#endif
  }
  return ActionNone; // ignore unknown input
}

int mc_print_at(int at, char *buf, int sz) {
  int l = 0;
  for (int i = 0; (i < MAXFLD) && (l < sz); i++) {
    const struct statf *sf = active_statf(i);
    if (sf) {
      // if there's no replies, show only packet counters
      const char *str = (host[at].recv || strchr("LDRS", sf->key)) ? net_elem(at, sf->key) : "";
      l += snprintf(buf + l, sz - l, "%*s", sf->len, str ? str : "");
    }
  }
  return l;
}

#ifdef WITH_MPLS
static int printw_mpls(const mpls_data_t *m) {
  for (int i = 0; i < m->n; i++) {
    int y;
    getyx(stdscr, y, __unused_int);
    printw("%s", mpls2str(&(m->label[i]), 4));
    if (move(y + 1, 0) == ERR)
      return ERR;
  }
  return OK;
}
#endif

static void printw_addr(int at, int ndx, int up) {
  ip_t *addr = &IP_AT_NDX(at, ndx);
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    printw("%s", fmt_ipinfo(at, ndx));
#endif
  if (!up)
    attron(A_BOLD);
#ifdef ENABLE_DNS
  const char *name = dns_ptr_lookup(at, ndx);
  if (name) {
    printw("%s", name);
    if (show_ips)
      printw(" (%s)", strlongip(addr));
  } else
#endif
    printw("%s", strlongip(addr));
  if (!up)
    attroff(A_BOLD);
}

#define BELL_AT	SAVED_PINGS - 3	// wait at least -i interval for reliability
static void seal_n_bell(int at, int max) {
  if (host[at].saved[BELL_AT] == CT_UNKN) {
    host[at].saved[BELL_AT] = CT_SEAL; // sealed
    if (bell_target)
      if (at != (max - 1))
        return;
    if (bell_audible) beep();
    if (bell_visible) flash();
  }
}

static int print_stat(int at, int y, int start, int max) { // statistics
  static char statbuf[1024];
  mc_print_at(at, statbuf, sizeof(statbuf));
  mvprintw(y, start, "%s", statbuf);
  if (bell_audible || bell_visible)
    seal_n_bell(at, max);
  return move(y + 1, 0);
}

static void print_addr_extra(int at, int y) { // mpls + multipath
  for (int ndx = 0; ndx < MAXPATH; ndx++) {  // multipath
    if (ndx == host[at].current)
      continue; // because already printed
    ip_t *addr = &IP_AT_NDX(at, ndx);
    if (!addr_exist(addr))
      break;
    printw("    ");
    printw_addr(at, ndx, host[at].up);
    getyx(stdscr, y, __unused_int);
    if (move(y + 1, 0) == ERR)
        break;
#ifdef WITH_MPLS
    if (enable_mpls)
      if (printw_mpls(&MPLS_AT_NDX(at, ndx)) == ERR)
        break;
#endif
  }
}

static void print_hops(int statx) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    int y;
    getyx(stdscr, y, __unused_int);
    move(y, 0);
    printw("%2d. ", at + 1);
    ip_t *addr = &CURRENT_IP(at);
    if (!addr_exist(addr)) {
      printw("%s", UNKN_ITEM);
      if (move(y + 1, 0) == ERR)
        break;
//    continue;
      if (at < (max - 1))
        if (print_stat(at, y, statx, max) == ERR)
          break;
    } else {
      printw_addr(at, host[at].current, host[at].up);
      if (print_stat(at, y, statx, max) == ERR)
        break;
#ifdef WITH_MPLS
      if (enable_mpls)
        printw_mpls(&CURRENT_MPLS(at));
#endif
      print_addr_extra(at, y);
    }
  }
  move(2, 0);
}

static chtype map1[] = {'.' | A_NORMAL, '>' | COLOR_PAIR(1)};
#define NUM_FACTORS2	8
static chtype map2[NUM_FACTORS2];
static double factors2[NUM_FACTORS2];
static int scale2[NUM_FACTORS2];
static int dm2_color_base;
static chtype map_na2[] = { ' ', '?', '>' | A_BOLD};
#ifdef WITH_UNICODE
#define NUM_FACTORS3_MONO	7	// without trailing char
#define NUM_FACTORS3		22
static cchar_t map3[NUM_FACTORS3];
static double factors3[NUM_FACTORS3];
static int scale3[NUM_FACTORS3];
static int dm3_color_base;
static cchar_t map_na3[3];
#endif

static void scale_map(int *scale, double *factors, int num) {
  int minval = INT_MAX;
  int maxval = -1;
  int max = net_max();
  for (int at = display_offset; at < max; at++) {
    for (int i = 0; i < SAVED_PINGS; i++) {
      int saved = host[at].saved[i];
      if (saved >= 0) {
        if (saved > maxval)
          maxval = saved;
        else if (saved < minval)
          minval = saved;
      }
    }
  }
  if (maxval < 0)
    return;
  int range = maxval - minval;
  for (int i = 0; i < num; i++)
    scale[i] = minval + range * factors[i];
}

static void dmode_scale_map(void) {
#ifdef WITH_UNICODE
  if (curses_mode == 3)
    scale_map(scale3, factors3, enable_color ? NUM_FACTORS3 : (NUM_FACTORS3_MONO + 1));
  else
#endif
    scale_map(scale2, factors2, NUM_FACTORS2);
}

static inline void dmode_init(double *factors, int num) {
  double inv = 1 / (double)num;
  for (int i = 0; i < num; i++) {
    double f = (i + 1) * inv;
    factors[i] = f * f;
  }
}

void mc_init(void) {
  // display mode 2
  dmode_init(factors2, NUM_FACTORS2);
#ifdef WITH_UNICODE
  // display mode 3
  dmode_init(factors3, enable_color ? NUM_FACTORS3 : (NUM_FACTORS3_MONO + 1));
#endif

  // Initialize block_map
  int block_split;
  block_split = (NUM_FACTORS2 - 2) / 2;
  if (block_split > 9)
    block_split = 9;
  for (int i = 1; i <= block_split; i++)
    map2[i] = '0' + i;
  for (int i = block_split + 1; i < NUM_FACTORS2 - 1; i++)
    map2[i] = 'a' + i - block_split - 1;
  map2[0] = map1[0];
  for (int i = 1; i < NUM_FACTORS2 - 1; i++)
    map2[i] |= COLOR_PAIR(dm2_color_base + i - 1);
  map2[NUM_FACTORS2 - 1] = map1[1] & A_CHARTEXT;
  map2[NUM_FACTORS2 - 1] |= (map2[NUM_FACTORS2 - 2] & A_ATTRIBUTES) | A_BOLD;

  map_na2[1] |= enable_color ? (map2[NUM_FACTORS2 - 1] & A_ATTRIBUTES) : A_BOLD;

#ifdef WITH_UNICODE
  for (int i = 0; i < NUM_FACTORS3_MONO; i++)
    map3[i].CCHAR_chars[0] = L'▁' + i;

  if (enable_color) {
    for (int i = 0; i < NUM_FACTORS3 - 1; i++) {
      int base = i / NUM_FACTORS3_MONO;
      map3[i].CCHAR_attr = COLOR_PAIR(dm3_color_base + base);
      if (i >= NUM_FACTORS3_MONO)
        map3[i].CCHAR_chars[0] = map3[i % NUM_FACTORS3_MONO].CCHAR_chars[0];
    }
    map3[NUM_FACTORS3 - 1].CCHAR_chars[0] = map1[1] & A_CHARTEXT;
    map3[NUM_FACTORS3 - 1].CCHAR_attr = map3[NUM_FACTORS3 - 2].CCHAR_attr | A_BOLD;
  } else
    map3[NUM_FACTORS3_MONO].CCHAR_chars[0] = map1[1] & A_CHARTEXT;

  for (int i = 0; i < (sizeof(map_na2) / sizeof(map_na2[0])); i++)
    map_na3[i].CCHAR_chars[0] = map_na2[i] & A_CHARTEXT;
  map_na3[1].CCHAR_attr = enable_color ? map3[NUM_FACTORS3 - 1].CCHAR_attr : A_BOLD;
  map_na3[2].CCHAR_attr = A_BOLD;
#endif
}

#define NA_MAP(map) { \
  if (saved_int == CT_UNSENT) \
    return map[0]; /* unsent ' ' */ \
  if ((saved_int == CT_UNKN) || (saved_int == CT_SEAL)) \
    return map[1]; /* no response '?' */ \
}

static chtype get_saved_ch(int saved_int) {
  NA_MAP(map_na2);
  if (curses_mode == 1)
    return map1[(saved_int <= scale2[NUM_FACTORS2 - 2]) ? 0 : 1];
  if (curses_mode == 2)
    for (int i = 0; i < NUM_FACTORS2; i++)
      if (saved_int <= scale2[i])
        return map2[i];
  return map_na2[2]; // UNKN
}

#ifdef WITH_UNICODE
static cchar_t* mtr_saved_cc(int saved_int) {
  NA_MAP(&map_na3);
  int num = enable_color ? NUM_FACTORS3 : (NUM_FACTORS3_MONO + 1);
  for (int i = 0; i < num; i++)
    if (saved_int <= scale3[i])
      return &map3[i];
  return &map_na3[2]; // UNKN
}
#endif

static void histogram(int statx, int cols) {
	int max = net_max();
	for (int at = net_min() + display_offset; at < max; at++) {
		int y;
		getyx(stdscr, y, __unused_int);
		move(y, 0);
		printw("%2d. ", at + 1);

		ip_t *addr = &CURRENT_IP(at);
		if (addr_exist(addr)) {
			if (!host[at].up)
				attron(A_BOLD);
#ifdef WITH_IPINFO
			if (ipinfo_ready())
				printw("%s", fmt_ipinfo(at, host[at].current));
#endif
#ifdef ENABLE_DNS
			const char *name = dns_ptr_lookup(at, host[at].current);
			printw("%s", name ? name : strlongip(addr));
#else
			printw("%s", strlongip(addr));
#endif
			if (!host[at].up)
				attroff(A_BOLD);
			mvprintw(y, statx, " ");
#ifdef WITH_UNICODE
			if (curses_mode == 3)
				for (int i = SAVED_PINGS - cols; i < SAVED_PINGS; i++)
					add_wch(mtr_saved_cc(host[at].saved[i]));
			else
#endif
				for (int i = SAVED_PINGS - cols; i < SAVED_PINGS; i++)
					addch(get_saved_ch(host[at].saved[i]));
			if (bell_audible || bell_visible)
				seal_n_bell(at, max);
		} else
			printw("%s", UNKN_ITEM);
		if (move(y + 1, 0) == ERR)
			break;
	}
}

int mc_statf_title(char *buf, int sz) {
  int l = 0;
  for (int i = 0; (i < MAXFLD) && (l < sz); i++ ) {
    const struct statf *sf = active_statf(i);
    if (sf)
      l += snprintf(buf + l, sz - l, "%*s", sf->len, sf->name);
  }
  buf[l] = 0;
  return l;
}

#ifdef WITH_UNICODE
static void mtr_print_scale3(int min, int max, int step) {
  for (int i = min; i < max; i += step) {
    addstr("  ");
    add_wch(&map3[i]);
    LENVALMIL(scale3[i]);
    printw(":%.*fms", _l, _v);
  }
  addstr("  ");
  add_wch(&map3[max]);
}
#endif

static inline int map2ch(int i) { return map2[i] & A_CHARTEXT; }

static void print_scale(void) {
  attron(A_BOLD);
  printw("Scale:");
  attroff(A_BOLD);
  if (curses_mode == 1) {
    addstr("  ");
    addch(map1[0] | A_BOLD);
    LENVALMIL(scale2[NUM_FACTORS2 - 2]);
    printw(" less than %.*fms   ", _l, _v);
    addch(map1[1] | (enable_color ? 0 : A_BOLD));
    addstr(" greater than ");
    addch(map1[0] | A_BOLD);
    addstr("   ");
    addch('?' | (enable_color ? (map2[NUM_FACTORS2 - 1] & A_ATTRIBUTES) : A_BOLD));
    addstr(" Unknown");
  } else if (curses_mode == 2) {
    if (enable_color) {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        addstr("  ");
        addch(map2[i]);
        LENVALMIL(scale2[i]);
        printw(":%.*fms", _l, _v);
      }
      addstr("  ");
      addch(map2[NUM_FACTORS2 - 1]);
    } else {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        LENVALMIL(scale2[i]);
        printw("  %c:%.*fms", map2ch(i), _l, _v);
      }
      printw("  %c", map2ch(NUM_FACTORS2 - 1));
    }
  }
#ifdef WITH_UNICODE
  else if (curses_mode == 3) {
    if (enable_color)
      mtr_print_scale3(1, NUM_FACTORS3 - 1, 2);
    else
      mtr_print_scale3(0, NUM_FACTORS3_MONO, 1);
  }
#endif
}

#define SET_IASP { if (!iargs_sp) iargs_sp = true; }
#define IASP (iargs_sp ? " " : "")
#define ADD_NTH_BIT_INFO(bit, what) { \
  if (NEQBIT(run_args, kept_args, (bit))) l += snprint_iarg((bit), buf + l, sz - l, (what)); }
static bool iargs_sp;
static int snprint_iarg(int bit, char *buf, int sz, const char *msg) {
  int l = snprintf(buf, sz, "%s%s%c", IASP, msg, CHKBIT(run_args, bit) ? '+' : '-');
  SET_IASP;
  return l;
}

int mc_snprint_args(char *buf, int sz) {
  iargs_sp = false;
  int l = snprintf(buf, sz, " (");
  ADD_NTH_BIT_INFO(RA_UDP, "udp");
  ADD_NTH_BIT_INFO(RA_TCP, "tcp");
#ifdef WITH_MPLS
  ADD_NTH_BIT_INFO(RA_MPLS, "mpls");
#endif
#ifdef WITH_IPINFO
  ADD_NTH_BIT_INFO(RA_ASN, "asn");
  ADD_NTH_BIT_INFO(RA_IPINFO, "ipinfo");
#endif
#ifdef ENABLE_DNS
  ADD_NTH_BIT_INFO(RA_DNS, "dns");
#endif
  ADD_NTH_BIT_INFO(RA_JITTER, "jitter");
  int chart = 0;
  if (CHKBIT(run_args, RA_DM0)) chart |= 1;
  if (CHKBIT(run_args, RA_DM1)) chart |= 2;
  if (chart) { l += snprintf(buf + l, sz - l, "%schart%u", IASP, chart); SET_IASP; }
  ADD_NTH_BIT_INFO(RA_CACHE, "cache");
  l += snprintf(buf + l, sz - l, ")");
  if (strnlen(buf, sizeof(buf)) == 3 /*" ()"*/) l = 0;
  if (NEQBIT(run_args, kept_args, RA_PAUSE)) l += snprintf(buf + l, sz - l, ": in pause");
  return l;
}

void mc_redraw(void) {
  static char linebuf[1024];  // seems enough for one line
  int maxx, maxy;
  int statx, staty = 4;
  erase();
  getmaxyx(stdscr, maxy, maxx);

  // title
  int l = snprintf(linebuf, sizeof(linebuf), "%s", mc_title);
  if (run_args != kept_args)
    l += mc_snprint_args(linebuf + l, sizeof(linebuf) - l);
  mvprintw(0, 0, "%*s", (maxx + l) / 2, linebuf);

  // hints and time
  mvprintw(1, 0, "Keys: ");
  attron(A_BOLD); addch('h'); attroff(A_BOLD); printw("ints ");
  attron(A_BOLD); addch('q'); attroff(A_BOLD); printw("uit\n");
  time_t t = time(NULL);
  int hlen = strnlen(srchost, 20);
  mvprintw(1, maxx - (hlen + 27), "%.*s: %s", hlen, srchost, ctime(&t));

  // main body
  if (curses_mode == 0) {
    statx = 4;	// indent: "NN. "
    int tlen = mc_statf_title(linebuf, sizeof(linebuf));
    attron(A_BOLD);
#ifdef WITH_IPINFO
    if (ipinfo_ready()) {
      char *header = ipinfo_header();
      if (header)
        mvprintw(staty - 1, statx, "%s", header);
      statx += ipinfo_width(); // indent: "NN. " + IPINFO
    }
#endif
    mvprintw(staty - 1, statx, "Host");
    l = maxx - tlen - 1;
    mvprintw(staty - 1, l > 0 ? l : 0, "%s", linebuf);
    if (is_custom_fld())
      l = snprintf(linebuf, sizeof(linebuf), "CUSTOMIZED-OUTPUT: %s", fld_active);
    else
      l = snprintf(linebuf, sizeof(linebuf), "Packets      Pings");
    l = l >= tlen ? maxx - l : maxx - tlen + 1;
    mvprintw(staty - 2, l > 0 ? l : 0, "%s", linebuf);
    attroff(A_BOLD);

    if (move(staty, 0) != ERR)
      print_hops(maxx - tlen - 1);

  } else {
    statx = STARTSTAT;
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      statx += ipinfo_width();
#endif
    int max_cols = (maxx <= (SAVED_PINGS + statx)) ? (maxx - statx) : SAVED_PINGS;
    statx -= 2;
    mvprintw(staty - 1, statx, " Last %3d pings", max_cols);
	if (move(staty, 0) != ERR) {
		attroff(A_BOLD);
		dmode_scale_map();
		histogram(statx, max_cols);
		int y;
		getyx(stdscr, y, __unused_int);
		int re = move(y + 1, 0);
		if (re != ERR)
			print_scale();
	}
  }

  refresh();
  move(maxy - 3, 0);
}


bool mc_open(void) {
  if (!initscr()) {
    WARNX("initscr() failed");
    return false;
  }
  raw();
  noecho();

  if (enable_color)
    if (!has_colors())
      enable_color = false;

  if (enable_color) {
    start_color();
    int bg_col = 0;
#ifdef HAVE_USE_DEFAULT_COLORS
    use_default_colors();
    if (use_default_colors() == OK)
      bg_col = -1;
#endif
    int i = 1;
    // curses_mode 1
    init_pair(i++, COLOR_YELLOW, bg_col);
    // curses_mode 2
    dm2_color_base = i;
    init_pair(i++, COLOR_GREEN, bg_col);
    init_pair(i++, COLOR_CYAN, bg_col);
    init_pair(i++, COLOR_BLUE, bg_col);
    init_pair(i++, COLOR_YELLOW, bg_col);
    init_pair(i++, COLOR_MAGENTA, bg_col);
    init_pair(i++, COLOR_RED, bg_col);
#ifdef WITH_UNICODE
    // display mode 3
    dm3_color_base = i;
    init_pair(i++, COLOR_GREEN, bg_col);
//    init_pair(i++, COLOR_YELLOW, COLOR_GREEN);
    init_pair(i++, COLOR_YELLOW, bg_col);
//    init_pair(i++, COLOR_RED, COLOR_YELLOW);
    init_pair(i++, COLOR_RED, bg_col);
    init_pair(i++, COLOR_RED, bg_col);
#endif
  }

  // init title
  int l = snprintf(mc_title, sizeof(mc_title), "%s", FULLNAME);
  if (mtr_args[0]) l += snprintf(mc_title + l, sizeof(mc_title) - l, " %s", mtr_args);
  l += snprintf(mc_title + l, sizeof(mc_title) - l, " %s", dsthost);

  mc_init();
  mc_redraw();
  curs_set(0);
  return true;
}


void mc_close(void) {
  addch('\n');
  endwin();
}

void mc_clear(void) {
  mc_close();
  mc_open();
}

