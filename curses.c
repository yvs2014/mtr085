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

#ifdef __sun /* ctime_r() */
#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#endif

#include "mtr-curses.h"
#include "common.h"
#include "nls.h"

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
#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

enum { LINEMAXLEN = 1024, HINT_YPOS = 2, HOSTINFOMAX = 30 };

static char screen_title[NAMELEN]; // progname + arguments + destination
static bool at_quit, screen_ready;
static unsigned title_len;

static size_t enter_smth(char *buf, size_t size, int y, int x) {
  move(y, x);
  int ch = 0, curs = curs_set(1);
  refresh();
  for (unsigned i = 0; ((ch = getch()) != '\n') && (i < size);) {
    addch((unsigned)ch | A_BOLD);
    refresh();
    buf[i++] = ch;
  }
  move(y, 0); clrtoeol(); refresh();
  if (curs != ERR) curs_set(curs);
  return strnlen(buf, size - 1);
}

static void enter_stat_fields(void) {
  char fields[MAXFLD + 1] = {0};
  int ch = 0, curs = curs_set(1);
  for (unsigned i = 0; ((ch = getch()) != '\n') && (i < sizeof(fields));) {
    int nth = 0;
    for (; nth < stat_max; nth++) if (ch == stats[nth].key) {
      addch((unsigned)ch | A_BOLD);
      refresh();
      fields[i++] = ch;
      break;
    }
    if (nth >= stat_max) // beep on too long
      beep();
  }
  if (fields[0]) set_fld_active(fields);
  if (curs != ERR) curs_set(curs);
}

static void mc_get_int(int *val, int min, int max,
    const char *what, const char *hint)
{
  mvprintw(HINT_YPOS, 0, "%s: %d", what, *val);
  if (hint)
    mvprintw(HINT_YPOS + 1, 0, "-> %s", hint);
  int xpos = what ? strlen(what) : 0;
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(entered, sizeof(entered), HINT_YPOS, xpos + 2)) {
    int num = limit_int(min, max, entered, what, 0);
    if (limit_error[0]) {
      printw("%s. %s ...", limit_error, ANYKEY_STR);
      refresh(); getch();
    } else
      *val = num;
  }
}

static inline void mc_key_h(void) { // help
  erase();
  mvprintw(2, 0,
"Commands:\n"
"  b <int>    set bit pattern in range 0..255, or random if it's negative\n"
"  c <int>    set number of cycles to run, or unlimit (<1)\n"
"  d          switch display mode\n"
#ifdef WITH_MPLS
"  e          toggle MPLS info\n"
#endif
"  f <int>    set first TTL (default 1)\n"
"  i <int>    set interval in seconds (default 1)\n"
"  j          toggle lattency/jitter stats (default latency)\n"
#ifdef WITH_IPINFO
"  l          toggle ASN lookup\n"
"  L          switch IP info\n"
#endif
"  m <int>    set max TTL (default 30)\n"
#ifdef ENABLE_DNS
"  n          toggle DNS\n"
#endif
"  o <str>    set fields to display (default 'LRS N BAWV')\n"
"  q          quit\n"
#ifdef IP_TOS
"  Q <int>    set ToS/QoS\n"
#endif
"  r          reset statistics\n"
"  s <int>    set payload size (default 56), randomly within size range if it's negative\n"
"  t          toggle TCP pings\n"
"  u          toggle UDP pings\n"
"  x          toggle cache mode\n"
"  +-         scroll up/down\n"
"  SPACE      pause/resume\n"
"\n"
"%s ...", ANYKEY_STR);
  getch();
}

static inline void mc_key_c(void) { // set number of cycles
  const char *prompt = "Number (unlimit 0) of cycles: ";
  mvaddstr(HINT_YPOS, 0, prompt); printw("%d", run_opts.cycles);
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(entered, sizeof(entered), HINT_YPOS, strlen(prompt))) {
    int num = limit_int(-1, INT_MAX, entered, "Number of cycles", 0);
    if (limit_error[0]) {
      printw("%s. %s ...", limit_error, ANYKEY_STR);
      refresh(); getch();
    } else {
      run_opts.cycles = num;
      OPT_SUM(cycles);
    }
  }
}

static inline void mc_key_o(void) { // set fields to display and their order
  const char what[] = "Fields";
  mvprintw(HINT_YPOS, 0, "%s: %s\n\n", what, fld_active);
  for (int i = 0; i < stat_max; i++) if (stats[i].hint)
    printw("  %c: %s\n", stats[i].key, stats[i].hint);
  move(HINT_YPOS, strlen(what) + 2);
  refresh();
  enter_stat_fields();
}

#ifdef IP_TOS
static inline void mc_key_Q(void) { // set QoS
#if defined(ENABLE_IPV6) && !defined(IPV6_TCLASS)
  if (af == AF_INET6) {
    mvprintw(HINT_YPOS,     0, "IPv6 traffic class is not supported");
    mvprintw(HINT_YPOS + 1, 0, "-> %s ...", ANYKEY_STR);
    getch();
  } else
#endif
  { int qos = run_opts.qos;
    mc_get_int(&qos, 0, UINT8_MAX, "QoS",
      "ToS bits: lowcost(1), reliability(2), throughput(4), lowdelay(8)");
    run_opts.qos = qos;
    OPT_SUM(qos);
  }
}
#endif

static inline void mc_key_s(void) { // set payload size
  const char *prompt = "Change payload size: ";
  mvaddstr(HINT_YPOS, 0, prompt);
  printw("%d", run_opts.size);
  const int max = MAXPACKET - MINPACKET;
  mvprintw(HINT_YPOS + 1, 0, "-> range[%d,%d], negative values are for random", -max, max);
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(entered, sizeof(entered), HINT_YPOS, strlen(prompt))) {
    int num = limit_int(-max, max, entered, "Payload size", 0);
    if (limit_error[0]) {
      printw("%s. %s ...", limit_error, ANYKEY_STR);
      refresh(); getch();
    } else {
      run_opts.size = num;
      OPT_SUM(size);
      reset_pldsize = true;
    }
  }
}

key_action_t mc_keyaction(void) {
  int ch = getch();
#ifdef KEY_RESIZE
#define GETCH_BATCH 100
  if (ch == KEY_RESIZE) { // cleanup by batch
    for (int i = 0; (ch == KEY_RESIZE) && (i < GETCH_BATCH); i++)
      ch = getch();
    if (ch == KEY_RESIZE) // otherwise flush
      flushinp();
  }
#undef GETCH_BATCH
#endif
  switch (ch) {
    case '+': return ActionScrollDown;
    case '-': return ActionScrollUp;
    case '?':
    case 'h':
      mc_key_h();
      break;
    case 'b': // bit pattern
      mc_get_int(&run_opts.pattern, -1, UINT8_MAX,
        "Bit Pattern", "range[0-255], random is -1");
      OPT_SUM(pattern);
      reset_pattern = true;
      break;
    case 'c': // number of cycles
      mc_key_c();
      break;
    case 'd': return ActionDisplay;
#ifdef WITH_MPLS
    case 'e': return ActionMPLS;
#endif
    case 'f': { // first ttl
      int minttl = run_opts.minttl;
      mc_get_int(&minttl, 1, run_opts.maxttl, "First TTL", NULL);
      run_opts.minttl = minttl;
      OPT_SUM(minttl);
    } break;
    case 'i': { // interval
      mc_get_int(&run_opts.interval, 1, INT_MAX, "Interval", NULL);
      OPT_SUM(interval);
    } break;
    case 'j': return ActionJitter;
#ifdef WITH_IPINFO
    case 'l': return ActionAS;
    case 'L': return ActionII;
#endif
    case 'm': { // max ttl
      int maxttl = run_opts.maxttl;
      mc_get_int(&maxttl, run_opts.minttl, MAXHOST - 1, "Max TTL", NULL);
      run_opts.maxttl = maxttl;
      OPT_SUM(maxttl);
    } break;
#ifdef ENABLE_DNS
    case 'n': return ActionDNS;
#endif
    case 'o': // fields to display and their order
      mc_key_o();
      title_len = 0;
      break;
    case ' ':
    case 'p': return ActionPauseResume;
    case  3 : // ^C
    case 'q':
      at_quit = true;
      return ActionQuit;
#ifdef IP_TOS
    case 'Q': // qos
      mc_key_Q();
      break;
#endif
    case 'r': return ActionReset;
    case 's': // payload size
      mc_key_s();
      break;
    case 't': return ActionTCP;
    case 'u': return ActionUDP;
    case 'x': return ActionCache;
    default: break;
  }
  return ActionNone; // ignore unknown input
}

#ifdef WITH_MPLS
static int printw_mpls(const mpls_data_t *m) {
  for (int i = 0; i < m->n; i++) {
    printw("%s", mpls2str(&(m->label[i]), 4));
    if (move(getcury(stdscr) + 1, 0) == ERR)
      return ERR;
  }
  return OK;
}
#endif

static void printw_addr(int at, int ndx) {
  t_ipaddr *addr = &IP_AT_NDX(at, ndx);
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    printw("%s", fmt_ipinfo(at, ndx));
#endif
  bool down = !host[at].up;
  if (down)
    attron(A_BOLD);
#ifdef ENABLE_DNS
  const char *name = dns_ptr_lookup(at, ndx);
  if (name) {
    printw("%s", name);
    if (run_opts.ips)
      printw(" (%s)", strlongip(addr));
  } else
#endif
    printw("%s", strlongip(addr));
  if (down)
    attroff(A_BOLD);
}

static void seal_n_bell(int at, int max) {
  const int bell_at = SAVED_PINGS - 3; // wait at least -i interval for reliability
  if (host[at].saved[bell_at] == CT_UNKN) {
    host[at].saved[bell_at] = CT_SEAL; // sealed
    if (run_opts.bell)
      if (at != (max - 1))
        return;
    if (run_opts.audible)
      beep();
    if (run_opts.visible)
      flash();
  }
}

static int print_stat(int at, int y, int x, int max) { // statistics
  if (move(y, x) == ERR) return ERR;
  for (unsigned i = 0; i < sizeof(fld_index); i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    // if there's no replies, show only packet counters
    const char *str = (host[at].recv || strchr("LDRS", stat->key)) ? net_elem(at, stat->key) : "";
    printw("%*s", stat->min, str ? str : "");
  }
  if (run_opts.audible || run_opts.visible)
    seal_n_bell(at, max);
  return move(y + 1, 0);
}

static void print_addr_extra(int at) { // mpls + multipath
  for (int ndx = 0; ndx < MAXPATH; ndx++) {  // multipath
    if (ndx == host[at].current)
      continue; // because already printed
    t_ipaddr *addr = &IP_AT_NDX(at, ndx);
    if (!addr_exist(addr))
      break;
    printw("    ");
    printw_addr(at, ndx);
    if (move(getcury(stdscr) + 1, 0) == ERR)
      break;
#ifdef WITH_MPLS
    if (run_opts.mpls)
      if (printw_mpls(&MPLS_AT_NDX(at, ndx)) == ERR)
        break;
#endif
  }
}

static void print_hops(int statx) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    int y = getcury(stdscr);
    if (move(y, 0) == ERR)
      break;
    printw(AT_FMT " ", at + 1);
    t_ipaddr *addr = &CURRENT_IP(at);
    if (addr_exist(addr)) {
      printw_addr(at, host[at].current);
      if (print_stat(at, y, statx, max) == ERR)
        break;
#ifdef WITH_MPLS
      if (run_opts.mpls)
        printw_mpls(&CURRENT_MPLS(at));
#endif
      print_addr_extra(at);
    } else {
      printw("%s", UNKN_ITEM);
      if (move(y + 1, 0) == ERR)
        break;
      if ((at < (max - 1)) && (print_stat(at, y, statx, max) == ERR))
        break;
    }
  }
  move(2, 0);
}

static chtype map1[] = {'.' | A_NORMAL, '>' | COLOR_PAIR(1)};
enum { NUM_FACTORS2 = 8 };
static chtype map2[NUM_FACTORS2];
static double factors2[NUM_FACTORS2];
static int scale2[NUM_FACTORS2];
static int dm2_color_base;
static chtype map_na2[] = { ' ', '?', '>' | A_BOLD};
#ifdef WITH_UNICODE
enum { NUM_FACTORS3_MONO =  7 }; // without trailing char
enum { NUM_FACTORS3      = 22 };
static cchar_t map3[NUM_FACTORS3];
static double factors3[NUM_FACTORS3];
static int scale3[NUM_FACTORS3];
static int dm3_color_base;
static cchar_t map_na3[3];
#endif

static void scale_map(int *scale, const double *factors, int num) {
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
  if ((maxval < 0) || (minval > maxval))
    return;
  int range = maxval - minval;
  for (int i = 0; i < num; i++)
    scale[i] = minval + range * factors[i];
}

static void dmode_scale_map(void) {
#ifdef WITH_UNICODE
  if (curses_mode == 3)
    scale_map(scale3, factors3, run_opts.color ? NUM_FACTORS3 : (NUM_FACTORS3_MONO + 1));
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

static void mc_init(void) {
  // display mode 2
  dmode_init(factors2, NUM_FACTORS2);
#ifdef WITH_UNICODE
  // display mode 3
  dmode_init(factors3, run_opts.color ? NUM_FACTORS3 : (NUM_FACTORS3_MONO + 1));
#endif

  { // map2 init
    map2[0] = map1[0];
    const int decimals = 9;
    int block_split = (NUM_FACTORS2 - 2) / 2;
    if (block_split > decimals)
      block_split = decimals;
    for (int i = 1; i <= block_split; i++)
      map2[i] = '0' + i;
    for (int i = block_split + 1, j = 0; i < NUM_FACTORS2 - 1; i++, j++)
      map2[i] = 'a' + j;
    for (int i = 1; i < NUM_FACTORS2 - 1; i++)
      map2[i] |= COLOR_PAIR(dm2_color_base + i - 1);
    map2[NUM_FACTORS2 - 1] = map1[1] & A_CHARTEXT;
    map2[NUM_FACTORS2 - 1] |= (map2[NUM_FACTORS2 - 2] & A_ATTRIBUTES) | A_BOLD;
    map_na2[1] |= run_opts.color ? (map2[NUM_FACTORS2 - 1] & A_ATTRIBUTES) : A_BOLD;
  }

#ifdef WITH_UNICODE
  { // map3 init
    for (int i = 0; i < NUM_FACTORS3_MONO; i++)
      map3[i].CCHAR_chars[0] = L'▁' + i;

    if (run_opts.color) {
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

    for (unsigned i = 0; i < ARRAY_SIZE(map_na2); i++)
      map_na3[i].CCHAR_chars[0] = map_na2[i] & A_CHARTEXT;
    map_na3[1].CCHAR_attr = run_opts.color ? map3[NUM_FACTORS3 - 1].CCHAR_attr : A_BOLD;
    map_na3[2].CCHAR_attr = A_BOLD;
  }
#endif
}

#define NA_MAP(map) { \
  if (saved_int == CT_UNSENT) \
    return (map)[0]; /* unsent ' ' */ \
  if ((saved_int == CT_UNKN) || (saved_int == CT_SEAL)) \
    return (map)[1]; /* no response '?' */ \
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
  int num = run_opts.color ? NUM_FACTORS3 : (NUM_FACTORS3_MONO + 1);
  for (int i = 0; i < num; i++)
    if (saved_int <= scale3[i])
      return &map3[i];
  return &map_na3[2]; // UNKN
}
#endif

static inline void histoaddr(int at, int max, int y, int x, int cols) {
  t_ipaddr *addr = &CURRENT_IP(at);
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
    mvprintw(y, x, " ");
#ifdef WITH_UNICODE
    if (curses_mode == 3)
      for (int i = SAVED_PINGS - cols; i < SAVED_PINGS; i++)
        add_wch(mtr_saved_cc(host[at].saved[i]));
    else
#endif
      for (int i = SAVED_PINGS - cols; i < SAVED_PINGS; i++)
        addch(get_saved_ch(host[at].saved[i]));
    if (run_opts.audible || run_opts.visible)
      seal_n_bell(at, max);
  } else printw("%s", UNKN_ITEM);
}

static void histogram(int x, int cols) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    int y = getcury(stdscr);
    if (move(y, 0) == ERR) break;
    printw(AT_FMT " ", at + 1);
    histoaddr(at, max, y, x, cols);
    if (move(y + 1, 0) == ERR) break;
  }
}

static int get_title_len(void) {
  int len = 0;
  for (unsigned i = 0; i < sizeof(fld_index); i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    len += (stat->min > stat->len) ? stat->min : stat->len + 1;
  }
  return (len < 0) ? 0 : len;
}

static int mc_fit_posx(int pos, int len) {
  return ((pos + len) > (getmaxx(stdscr) - 1)) ? (getmaxx(stdscr) - len - 1) : pos;
}

static void mc_stat_title(int x, int y) {
  if (move(y, x) == ERR) return;
  bool custom = is_custom_fld();
  for (unsigned i = 0; i < sizeof(fld_index); i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    int pad = stat->min - stat->len;
    if (!i || (i == 3)) { // add subtitles
      int curx = getcurx(stdscr);
      int pos  = curx + ((pad > 0) ? pad : 1);
      if (!i && custom) {
        int len = ustrlen(FIELDS_STR) + 2 + strnlen(fld_active, MAXFLD);
        mvprintw(y - 1, mc_fit_posx(pos, len), "%s: %s", FIELDS_STR, fld_active);
      } else if (!custom) {
        const char *sub = i ? PINGS_STR : PACKETS_STR;
        int len = ustrlen(sub);
        mvprintw(y - 1, mc_fit_posx(pos, len), "%s", i ? PINGS_STR : PACKETS_STR);
      }
      move(y, curx);
    }
    printw("%*s%s", (pad > 0) ? pad : 1, "", stat->name ? stat->name : "");
  }
}

#ifdef WITH_UNICODE
static void mtr_print_scale3(int min, int max, int step) {
  for (int i = min; i < max; i += step) {
    addstr("  ");
    add_wch(&map3[i]);
    if (scale3[i] > 0) {
      LENVALMIL(scale3[i]);
      printw(":%.*fms", _l, _v);
    }
  }
  addstr("  ");
  add_wch(&map3[max]);
}
#endif

static inline int map2ch(int ndx) { return map2[ndx] & A_CHARTEXT; }

static void print_scale(void) {
  attron(A_BOLD);
  printw("Scale:");
  attroff(A_BOLD);
  if (curses_mode == 1) {
    addstr("  ");
    addch(map1[0] | A_BOLD);
    LENVALMIL(scale2[NUM_FACTORS2 - 2]);
    printw(" less than %.*fms   ", _l, _v);
    addch(map1[1] | (run_opts.color ? 0 : A_BOLD));
    printw(" more than %.*fms   ", _l, _v);
    addch('?' | (run_opts.color ? (map2[NUM_FACTORS2 - 1] & A_ATTRIBUTES) : A_BOLD));
    addstr(" Unknown");
  } else if (curses_mode == 2) {
    if (run_opts.color) {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        addstr("  ");
        addch(map2[i]);
        if (scale2[i] > 0) {
          LENVALMIL(scale2[i]);
          printw(":%.*fms", _l, _v);
        }
      }
      addstr("  ");
      addch(map2[NUM_FACTORS2 - 1]);
    } else {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        if (scale2[i] > 0) {
          LENVALMIL(scale2[i]);
          printw("  %c:%.*fms", map2ch(i), _l, _v);
        }
      }
      printw("  %c", map2ch(NUM_FACTORS2 - 1));
    }
  }
#ifdef WITH_UNICODE
  else if (curses_mode == 3) {
    if (run_opts.color)
      mtr_print_scale3(1, NUM_FACTORS3 - 1, 2);
    else
      mtr_print_scale3(0, NUM_FACTORS3_MONO, 1);
  }
#endif
}

#define IASP (iargs_sp ? " " : "")
#define BOOL_OPT2STR(tag, what) do {  \
  if (run_opts.tag != ini_opts.tag) { \
    len += snprint_iarg(run_opts.tag, buf + len, size - len, (what)); } \
} while (0)
#define INT_OPT2STR(tag, what) do { \
  if (run_opts.tag != ini_opts.tag)   \
    ADD_INT_INFO(what, run_opts.tag); \
} while (0)
#define ADD_INT_INFO(what, value) do { \
  int inc = snprintf(buf + len, size - len, "%s" what, IASP, (value)); \
  if (inc > 0)     \
    len += inc;    \
  iargs_sp = true; \
} while (0)

static bool iargs_sp;
static int snprint_iarg(bool on, char *buf, int size, const char *msg) {
  int len = snprintf(buf, size, "%s%c%s", IASP, on ? '+' : '-', msg);
  iargs_sp = true;
  return (len > 0) ? len : 0;
}

static int mc_snprint_args(char *buf, size_t size) {
  iargs_sp = false;
  int len = snprintf(buf, size, " (");
  if (len < 0)
    len = 0;
  BOOL_OPT2STR(udp,    "udp");
  BOOL_OPT2STR(tcp,    "tcp");
#ifdef WITH_MPLS
  BOOL_OPT2STR(mpls,   "mpls");
#endif
#ifdef WITH_IPINFO
  BOOL_OPT2STR(asn,    "asn");
  BOOL_OPT2STR(ipinfo, "ipinfo");
#endif
#ifdef ENABLE_DNS
  BOOL_OPT2STR(dns,    "dns");
#endif
  BOOL_OPT2STR(jitter, "jitter");
  if (run_opts.chart != ini_opts.chart)
    ADD_INT_INFO("chart%u", run_opts.chart);
  //
  INT_OPT2STR(pattern,  "patt=%d");
  INT_OPT2STR(interval, "dt=%d");
  INT_OPT2STR(cycles,   "cycles=%d");
  INT_OPT2STR(minttl,   "ttl>=%u");
  INT_OPT2STR(maxttl,   "ttl<=%u");
  INT_OPT2STR(qos,      "qos=%u");
  INT_OPT2STR(size,     "size=%d");
  //
  BOOL_OPT2STR(oncache, "cache");
  { int inc = snprintf(buf + len, size - len, ")"); if (inc > 0) len += inc; }
  if (strnlen(buf, sizeof(buf)) == 3 /*" ()"*/)
    len = 0;
  if (run_opts.pause != ini_opts.pause) {
    int inc = snprintf(buf + len, size - len, ": in pause");
    if (inc > 0) len += inc;
  }
  return (len > 0) ? len : 0;
}
#undef SET_IASP
#undef IASP
#undef ADD_NTH_BIT_INFO

static void mc_statmode(void) {
  int statx = 4; // x-indent: "NN. "
  int staty = 4; // y-indent: main_title + hint_line + field_titles[2]
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
  if (!title_len) title_len = get_title_len();
  int x = getmaxx(stdscr) - title_len - 1;
  if (x < 0) x = 0;
  mc_stat_title(x, staty - 1);
  attroff(A_BOLD);
  if (move(staty, 0) != ERR)
    print_hops(x);
}

static inline void mc_histmode(void) {
  int statx = HOSTINFOMAX;
  int staty = 4; // y-indent: main_title + hint_line + field_titles[2]
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    statx += ipinfo_width();
#endif
  int maxx = getmaxx(stdscr);
  int max_cols = (maxx <= (SAVED_PINGS + statx)) ? (maxx - statx) : SAVED_PINGS;
  statx -= 2;
  mvprintw(staty - 1, statx, " Last %3d pings", max_cols);
  if (move(staty, 0) != ERR) {
    attroff(A_BOLD);
    dmode_scale_map();
    histogram(statx, max_cols);
    if (move(getcury(stdscr) + 1, 0) != ERR)
      print_scale();
  }
}

void mc_redraw(void) {
  static char linebuf[LINEMAXLEN];
  erase();
  { // title
    int len = 0, inc = snprintf(linebuf, sizeof(linebuf), "%s", screen_title);
    if (inc > 0) len += inc;
    if (opt_sum.un)
      len += mc_snprint_args(linebuf + len, sizeof(linebuf) - len);
    mvprintw(0, 0, "%*s", (getmaxx(stdscr) + len) / 2, linebuf);
  }
  { // hints and time
    mvprintw(1, 0, "%s: ", OPTS_STR);
    attron(A_BOLD); addch('h'); attroff(A_BOLD); printw("ints ");
    attron(A_BOLD); addch('q'); attroff(A_BOLD); printw("uit\n");
    time_t now = time(NULL);
    int maxx = getmaxx(stdscr);
#ifdef HAVE_CTIME_R
    char str[32];
    char *tm = (now > 0) ? ctime_r(&now, str) : NULL;
#else
    char *tm = (now > 0) ? ctime(&now) : NULL;
#endif
    int inc = snprintf(linebuf, sizeof(linebuf),
      "%.*s: %s", (int)strnlen(srchost, maxx / 2), srchost, tm ? tm : "");
    int len = (inc > 0) ? inc : 0;
    mvaddstr(1, maxx - len, linebuf);
  }
  // main body
  (curses_mode == 0) ? mc_statmode() : mc_histmode();
  refresh();
}


bool mc_open(void) {
  screen_ready = initscr();
  if (!screen_ready) {
    warnx("initscr() failed");
    return false;
  }
  raw();
  noecho();

  if (run_opts.color)
    if (!has_colors())
      run_opts.color = false;

  if (run_opts.color) {
    start_color();
    short bg_col = 0;
#ifdef HAVE_USE_DEFAULT_COLORS
    use_default_colors();
    if (use_default_colors() == OK)
      bg_col = -1;
#endif
    short pair = 1;
    // curses_mode 1
    init_pair(pair++, COLOR_YELLOW,  bg_col);
    // curses_mode 2
    dm2_color_base = pair;
    init_pair(pair++, COLOR_GREEN,   bg_col);
    init_pair(pair++, COLOR_CYAN,    bg_col);
    init_pair(pair++, COLOR_BLUE,    bg_col);
    init_pair(pair++, COLOR_YELLOW,  bg_col);
    init_pair(pair++, COLOR_MAGENTA, bg_col);
    init_pair(pair++, COLOR_RED,     bg_col);
#ifdef WITH_UNICODE
    // display mode 3
    dm3_color_base = pair;
    init_pair(pair++, COLOR_GREEN,   bg_col);
    init_pair(pair++, COLOR_YELLOW,  bg_col);
    init_pair(pair++, COLOR_RED,     bg_col);
    init_pair(pair++, COLOR_RED,     bg_col);
#endif
  }

  // init title
  { int inc = snprintf(screen_title, sizeof(screen_title), "%s", PACKAGE_NAME);
    int len = (inc > 0) ? inc : 0;
    if (mtr_args[0]) {
      inc = snprintf(screen_title + len, sizeof(screen_title) - len, " %s", mtr_args);
      if (inc > 0) len += inc;
    }
    snprintf(screen_title + len, sizeof(screen_title) - len, " %s", dsthost); }

  mc_init();
  mc_redraw();
  curs_set(0);
  return true;
}

void mc_confirm(void) {
  if (at_quit || !stdscr || !screen_ready)
    return;
  at_quit = true;
  const char *mesg = "Press any key to quit...";
  int y = getmaxy(stdscr) - 1;
  move(y - 1, 0); clrtoeol();
  move(y,     0); clrtoeol();
  mvaddstr(y - 1, (getmaxx(stdscr) - strlen(mesg)) / 2, mesg);
  flushinp();
  getch();
}

void mc_close(void) {
  if (stdscr && screen_ready) {
    endwin();
    screen_ready = false;
  }
}

void mc_clear(void) {
  mc_close();
  mc_open();
}

