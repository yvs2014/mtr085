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
#include <string.h>
#include <sys/types.h>

#include "common.h"
#include "nls.h"
#include "tui.h"

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

#define MSEC_FMT "%.*f %s"

enum { LINEMAXLEN = 1024, HINT_YPOS = 2, HOSTINFOMAX = 30 };

static char screen_title[NAMELEN]; // progname + arguments + destination
static uint screen_title_ulen;
static bool at_quit, screen_ready;
static int stat_title_len = -1;
static int cached_title_ulen = -1;

static size_t enter_smth(char *buf, size_t size, int y, int x) {
  move(y, x);
  int ch = 0, curs = curs_set(1);
  refresh();
  for (uint i = 0; ((ch = getch()) != '\n') && (i < size);) {
    addch((uint)ch | A_BOLD);
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
  for (uint i = 0; ((ch = getch()) != '\n') && (i < sizeof(fields));) {
    int nth = 0;
    for (; nth < stat_max; nth++) if (ch == stats[nth].key) {
      addch((uint)ch | A_BOLD);
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
  uint xpos = what ? ustrnlen(what, COLS) : 0;
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(entered, sizeof(entered), HINT_YPOS, xpos + 2)) {
    int num = limit_int(min, max, entered, what, 0);
    if (limit_error[0]) {
      printw("%s. %s ...", limit_error, ANYCONT_STR);
      refresh(); getch();
    } else
      *val = num;
  }
}

static inline void mc_key_h(void) { // help
  t_cmd_hint cmd[] = {
    {.key = "b", .hint = CMD_B_STR,  .type = CH_INT},
    {.key = "c", .hint = CMD_C_STR,  .type = CH_INT},
    {.key = "d", .hint = CMD_D_STR},
#ifdef WITH_MPLS
    {.key = "e", .hint = CMD_E_STR},
#endif
    {.key = "f", .hint = CMD_F_STR,  .type = CH_INT},
    {.key = "i", .hint = CMD_I_STR,  .type = CH_INT},
    {.key = "j", .hint = CMD_J_STR},
#ifdef WITH_IPINFO
    {.key = "l", .hint = CMD_L_STR},
    {.key = "L", .hint = CMD_LL_STR},
#endif
    {.key = "m", .hint = CMD_M_STR,  .type = CH_INT},
    {.key = "n", .hint = CMD_N_STR},
    {.key = "o", .hint = CMD_O_STR,  .type = CH_STR},
    {.key = "q", .hint = CMD_Q_STR},
#ifdef IP_TOS
    {.key = "Q", .hint = CMD_QQ_STR, .type = CH_INT},
#endif
    {.key = "r", .hint = CMD_R_STR},
    {.key = "s", .hint = CMD_S_STR,  .type = CH_INT},
    {.key = "t", .hint = CMD_T_STR},
    {.key = "u", .hint = CMD_U_STR},
    {.key = "x", .hint = CMD_X_STR},
    {.key = "+-",      .hint = CMD_PM_STR},
    {.key = SPACE_STR, .hint = CMD_SP_STR},
  };
  erase();
  int x = 2, y = 2;
#define INDENT 12
  mvprintw(x++, 0, "%s:", COMMANDS_STR);
  for (uint i = 0; i < ARRAY_LEN(cmd); i++) {
    int pad = INDENT - ustrnlen(cmd[i].key, INDENT);
    const char *type = cmd[i].type == CH_INT ? CH_NUM_STR :
                       cmd[i].type == CH_STR ? CH_STR_STR : NULL;
    if (type) {
      pad -= ustrnlen(type, COLS) + 1;
      mvprintw(x++, y, "%s %s%*s %s", cmd[i].key, type, (pad < 0) ? 0 : pad, "", cmd[i].hint);
    } else
      mvprintw(x++, y, "%s%*s %s", cmd[i].key, (pad < 0) ? 0 : pad, "", cmd[i].hint);
  }
#undef INDENT
  x++;
  mvprintw(x++, 0, "%s ...", ANYCONT_STR);
  getch();
}

static inline void mc_key_c(void) { // set number of cycles
  mvprintw(HINT_YPOS, 0, "%s (%s): %d", CYCLESNO_STR, CYCLE0NO_STR, run_opts.cycles);
  int xpos = ustrnlen(CYCLESNO_STR, COLS / 2 - 2) + 2 + ustrnlen(CYCLE0NO_STR, COLS / 2 - 3) + 3;
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(entered, sizeof(entered), HINT_YPOS, xpos)) {
    int num = limit_int(0, INT_MAX, entered, CYCLESNO_STR, 0);
    if (limit_error[0]) {
      printw("%s. %s ...", limit_error, ANYCONT_STR);
      refresh(); getch();
    } else {
      run_opts.cycles = num;
      OPT_SUM(cycles);
    }
  }
}

static inline void mc_key_o(void) { // set fields to display and their order
  mvprintw(HINT_YPOS, 0, "%s: %s\n\n", FIELDS_STR, fld_active);
  for (int i = 0; i < stat_max; i++) if (stats[i].hint)
    printw("  %c: %s\n", stats[i].key, stats[i].hint);
  move(HINT_YPOS, ustrnlen(FIELDS_STR, COLS - 2) + 2);
  refresh();
  enter_stat_fields();
}

#ifdef IP_TOS
static inline void mc_key_Q(void) { // set QoS
#if defined(ENABLE_IPV6) && !defined(IPV6_TCLASS)
  if (af == AF_INET6) {
    mvprintw(HINT_YPOS,     0, "%s", TCLASS6_ERR);
    mvprintw(HINT_YPOS + 1, 0, "-> %s ...", ANYCONT_STR);
    getch();
  } else
#endif
  { int qos = run_opts.qos;
    mc_get_int(&qos, 0, UINT8_MAX, QOSTOS_STR, TOS_HINT_STR);
    run_opts.qos = qos;
    OPT_SUM(qos);
  }
}
#endif

static inline void mc_key_s(void) { // set payload size
  mvprintw(HINT_YPOS, 0, "%s: %d", PSIZE_CHNG_STR, run_opts.size);
  const int max = MAXPACKET - MINPACKET;
  mvprintw(HINT_YPOS + 1, 0, "-> %s[%d,%d], %s", RANGE_STR, -max, max, NEG4RND_STR);
  char entered[MAXFLD + 1] = {0};
  int xpos = ustrnlen(PSIZE_CHNG_STR, COLS - 2) + 2;
  if (enter_smth(entered, sizeof(entered), HINT_YPOS, xpos)) {
    int num = limit_int(-max, max, entered, PSIZE_STR, 0);
    if (limit_error[0]) {
      printw("%s. %s ...", limit_error, ANYCONT_STR);
      refresh(); getch();
    } else {
      run_opts.size = num;
      OPT_SUM(size);
      reset_pldsize = true;
    }
  }
}

static key_action_t keyaction_body(int ch) {
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
      mc_get_int(&run_opts.pattern, -1, UINT8_MAX, BITPATT_STR, RANGENEG_STR);
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
      mc_get_int(&minttl, 1, run_opts.maxttl, MINTTL_STR, NULL);
      run_opts.minttl = minttl;
      OPT_SUM(minttl);
    } break;
    case 'i': { // interval
      mc_get_int(&run_opts.interval, 1, INT_MAX, GAPINSEC_STR, NULL);
      OPT_SUM(interval);
    } break;
    case 'j':
      stat_title_len = -1;
      return ActionJitter;
#ifdef WITH_IPINFO
    case 'l': return ActionAS;
    case 'L': return ActionII;
#endif
    case 'm': { // max ttl
      int maxttl = run_opts.maxttl;
      mc_get_int(&maxttl, run_opts.minttl, MAXHOST - 1, MAXTTL_STR, NULL);
      run_opts.maxttl = maxttl;
      OPT_SUM(maxttl);
    } break;
#ifdef ENABLE_DNS
    case 'n': return ActionDNS;
#endif
    case 'o': // fields to display and their order
      mc_key_o();
      stat_title_len = -1;
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

key_action_t tui_keyaction(void) {
  // wrapper to keyaction_body(): reset 'title_cache' if it needs
  int ch = getch();
  switch (ch) {
    case 'b': // bit pattern
    case 'c': // number of cycles
    case 'd': // ActionDisplay;
#ifdef WITH_MPLS
    case 'e': // ActionMPLS;
#endif
    case 'f': // first ttl
    case 'i': // interval
    case 'j': // ActionJitter
#ifdef WITH_IPINFO
    case 'l': // ActionAS;
    case 'L': // ActionII;
#endif
    case 'm': // max ttl
#ifdef ENABLE_DNS
    case 'n': // ActionDNS;
#endif
    case ' ':
    case 'p': // ActionPauseResume;
#ifdef IP_TOS
    case 'Q': // qos
#endif
    case 's': // payload size
    case 't': // ActionTCP;
    case 'u': // ActionUDP;
    case 'x': // ActionCache;
      cached_title_ulen = -1;
      break;
    default: break;
  }
  return keyaction_body(ch);
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
  if (ipinfo_ready()) {
    char info[NAMELEN] = {0};
    ipinfo_data_fix(info, sizeof(info), at, ndx);
    if (info[0])
      printw("%s", info);
  }
#endif
  bool down = !host[at].up;
  if (down)
    attron(A_BOLD);
#ifdef ENABLE_DNS
  const char *name = dns_ptr_lookup(at, ndx);
  if (name) {
    printw("%s", name);
    if (run_opts.both)
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

static void print_statline(int at, const t_stat *stat) {
  // if there's no replies, show only packet counters
  const char *str = (host[at].recv || strchr("LDRS", stat->key)) ? net_elem(at, stat->key) : "";
  printw("%*s", stat->min, str ? str : "");
}

static int print_stat(int at, int y, int x, int max) { // statistics
  if (move(y, x) == ERR) return ERR;
  foreach_stat(at, print_statline, 0);
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
  if (chart_mode == 3)
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

    for (uint i = 0; i < ARRAY_LEN(map_na2); i++)
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
  if (chart_mode == 1)
    return map1[(saved_int <= scale2[NUM_FACTORS2 - 2]) ? 0 : 1];
  if (chart_mode == 2)
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
    if (ipinfo_ready()) {
      char info[NAMELEN] = {0};
      ipinfo_data_fix(info, sizeof(info), at, host[at].current);
      if (info[0])
        printw("%s", info);
    }
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
    if (chart_mode == 3)
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

static int get_stat_title_len(void) {
  int len = 0;
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (stat) len += (stat->min > stat->len) ? stat->min : stat->len + 1;
  }
  return (len < 0) ? 0 : len;
}

static int mc_fit_posx(int pos, int len) {
  int lcols = COLS - 1 - len;
  return (pos < lcols) ? pos : lcols;
}

static void mc_stat_title(int x, int y) {
  if (move(y, x) == ERR) return;
  bool custom = is_custom_fld();
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    int pad = stat->min - stat->len;
    if (!i || (i == 3)) { // add subtitles
      int curx = getcurx(stdscr);
      int pos  = curx + ((pad > 0) ? pad : 1);
      if (!i && custom) {
        int len = ustrnlen(USR_FIELDS_STR, COLS - 2) + 2 + strnlen(fld_active, MAXFLD);
        mvprintw(y - 1, mc_fit_posx(pos, len), "%s: %s", USR_FIELDS_STR, fld_active);
      } else if (!custom) {
        const char *sub = i ? PINGS_STR : PACKETS_STR;
        int len = ustrnlen(sub, COLS);
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
      printw(":" MSEC_FMT, _l, _v, MSEC_STR);
    }
  }
  addstr("  ");
  add_wch(&map3[max]);
}
#endif

static inline int map2ch(int ndx) { return map2[ndx] & A_CHARTEXT; }

static void print_scale(void) {
  attron(A_BOLD);
  printw("%s:", SCALE_STR);
  attroff(A_BOLD);
  if (chart_mode == 1) {
    addstr("  ");
    addch(map1[0] | A_BOLD);
    LENVALMIL(scale2[NUM_FACTORS2 - 2]);
    printw(" %s " MSEC_FMT "   ", LESSTHAN_STR, _l, _v, MSEC_STR);
    addch(map1[1] | (run_opts.color ? 0 : A_BOLD));
    printw(" %s " MSEC_FMT "   ", MORETHAN_STR, _l, _v, MSEC_STR);
    addch('?' | (run_opts.color ? (map2[NUM_FACTORS2 - 1] & A_ATTRIBUTES) : A_BOLD));
    printw(" %s", UNKNOWN_STR);
  } else if (chart_mode == 2) {
    if (run_opts.color) {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        addstr("  ");
        addch(map2[i]);
        if (scale2[i] > 0) {
          LENVALMIL(scale2[i]);
          printw(":" MSEC_FMT, _l, _v, MSEC_STR);
        }
      }
      addstr("  ");
      addch(map2[NUM_FACTORS2 - 1]);
    } else {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        if (scale2[i] > 0) {
          LENVALMIL(scale2[i]);
          printw("  %c:" MSEC_FMT, map2ch(i), _l, _v, MSEC_STR);
        }
      }
      printw("  %c", map2ch(NUM_FACTORS2 - 1));
    }
  }
#ifdef WITH_UNICODE
  else if (chart_mode == 3) {
    if (run_opts.color)
      mtr_print_scale3(1, NUM_FACTORS3 - 1, 2);
    else
      mtr_print_scale3(0, NUM_FACTORS3_MONO, 1);
  }
#endif
}

#define IASP ((len > iasp) ? " " : "")

#define ADD_FMT_ARG(fmt, ...) do {   \
  int max = size - len;              \
  if (max <= 0) return size;         \
  int inc = snprinte(buf + len, max, \
    fmt, __VA_ARGS__);               \
  if (inc < 0) return len;           \
  else if (inc > 0) len += inc;      \
} while (0)

#define BOOL_OPT2STR(tag, msg) do {   \
  if (run_opts.tag != ini_opts.tag)   \
    ADD_FMT_ARG("%s%c%s", IASP,       \
      run_opts.tag ? '+' : '-', msg); \
} while (0)

#define INT_OPT2STR(tag, prfx, fmt) do {               \
  if (run_opts.tag != ini_opts.tag)                    \
    ADD_FMT_ARG("%s%s" fmt, IASP, prfx, run_opts.tag); \
} while (0)

static int mc_print_args(char buf[], size_t size) NONNULL(1);
static int mc_print_args(char buf[], size_t size) {
  int len = snprinte(buf, size, " (");
  if (len < 0) return len;
  int iasp = len;
  BOOL_OPT2STR(udp,    PAR_UDP_STR);
  BOOL_OPT2STR(tcp,    PAR_TCP_STR);
#ifdef WITH_MPLS
  BOOL_OPT2STR(mpls,   PAR_MPLS_STR);
#endif
#ifdef WITH_IPINFO
  BOOL_OPT2STR(asn,    PAR_ASN_STR);
  BOOL_OPT2STR(ipinfo, IPINFO_STR);
#endif
#ifdef ENABLE_DNS
  BOOL_OPT2STR(dns,    PAR_DNS_STR);
#endif
  BOOL_OPT2STR(jitter, PAR_JITTER_STR);
  //
  INT_OPT2STR(chart,    PAR_CHART_STR, "%u");
  //
  INT_OPT2STR(pattern,  PAR_PATT_STR, "=%d");
  INT_OPT2STR(interval, PAR_DT_STR, "=%d");
  INT_OPT2STR(cycles,   PAR_CYCLES_STR, "=%d");
  INT_OPT2STR(minttl,   PAR_TTL_STR, ">=%u");
  INT_OPT2STR(maxttl,   PAR_TTL_STR, "<=%u");
  INT_OPT2STR(qos,      PAR_QOS_STR, "=%u");
  INT_OPT2STR(size,     PAR_SIZE_STR, "=%d");
  //
  BOOL_OPT2STR(oncache, PAR_CACHE_STR);
  //
  ADD_FMT_ARG("%c", ')');
#define EMPTY_ARGS " ()"
  if (!strncmp(buf, EMPTY_ARGS, sizeof(EMPTY_ARGS)))
    len = 0;
#undef EMPTY_ARGS
  if (run_opts.pause != ini_opts.pause)
    ADD_FMT_ARG(": %s", PAR_PAUSED_STR);
  return (len > (int)size) ? (int)size : len;
}
#undef IASP
#undef ADD_FMT_ARG
#undef INT_OPT2STR
#undef BOOL_OPT2STR

static void display_stats(void) {
  int statx = 4; // x-indent: "NN. "
  int staty = 4; // y-indent: main_title + hint_line + field_titles[2]
  attron(A_BOLD);
#ifdef WITH_IPINFO
  if (ipinfo_ready()) {
    char info[NAMELEN] = {0};
    ipinfo_head_fix(info, sizeof(info));
    if (info[0])
      mvprintw(staty - 1, statx, "%s", info);
    statx += ipinfo_width(); // indent: "NN. " + IPINFO
  }
#endif
  mvprintw(staty - 1, statx, "%s", HOST_STR);
  if (stat_title_len < 0)
    stat_title_len = get_stat_title_len();
  int x = COLS - stat_title_len - 1;
  if (x < 0) x = 0;
  mc_stat_title(x, staty - 1);
  attroff(A_BOLD);
  if (move(staty, 0) != ERR)
    print_hops(x);
}

static inline void display_charts(void) {
  int statx = HOSTINFOMAX;
  int staty = 4; // y-indent: main_title + hint_line + field_titles[2]
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    statx += ipinfo_width();
#endif
  int max_cols = (COLS <= (SAVED_PINGS + statx)) ? (COLS - statx) : SAVED_PINGS;
  statx -= 2;
  mvprintw(staty - 1, statx, "%s: %d %s", HISTOGRAM_STR, max_cols, HCOLS_STR);
  if (move(staty, 0) != ERR) {
    attroff(A_BOLD);
    dmode_scale_map();
    histogram(statx, max_cols);
    if (move(getcury(stdscr) + 1, 0) != ERR)
      print_scale();
  }
}

static inline void mc_print_title(void) {
  static char title_cache[LINEMAXLEN];
  if (cached_title_ulen < 0) { // generate title and cache it
    char buff[LINEMAXLEN] = {0};
    const char *pretitle = screen_title;
    if (opt_sum.un) {
      int len = snprinte(buff, sizeof(buff), "%s", screen_title);
      if (len >= 0) {
        pretitle = buff;
        int inc = mc_print_args(buff + len, sizeof(buff) - len);
        if (inc < 0) pretitle = screen_title; // else len += inc;
      }
    }
    memset(title_cache, 0, sizeof(title_cache));
    int len = snprinte(title_cache, sizeof(title_cache), "%s", pretitle);
    if (len >= 0)
      cached_title_ulen = ustrnlen(title_cache, COLS);
  }
  //
  const char *title = NULL;
  if (cached_title_ulen > 0)
    title = title_cache;
  else {
    title = screen_title;
    cached_title_ulen = screen_title_ulen;
  }
  if (title && *title)
    mvprintw(0, 0, "%*s", (COLS + cached_title_ulen) / 2, title);
}

static inline void mc_print_hints_n_time(void) {
  mvprintw(1, 0, "%s: ", OPTS_STR);
  attron(A_BOLD); addch('h'); attroff(A_BOLD); printw("%s ", _HINTS_STR);
  attron(A_BOLD); addch('q'); attroff(A_BOLD); printw("%s\n", _QUIT_STR);
  char buff[LINEMAXLEN] = {0};
  // source host
  int len = snprinte(buff, sizeof(buff), "%.*s", (int)strnlen(srchost, COLS / 2), srchost);
  if (len < 0)
    return;
  // timestamp (note: not mandatory)
  char str[64] = {0};
  const char *date = datetime(time(NULL), str, sizeof(str));
  if (date && date[0])
    snprinte(buff + len, sizeof(buff) - len, ": %s", date);
  //
  if ((len > 0) && buff[0]) // rigth aligned
    mvaddstr(1, COLS - ustrnlen(buff, sizeof(buff)) - 1, buff);
}

static inline void mc_print_main_body(void) {
  chart_mode ? display_charts() : display_stats();
}

void tui_redraw(void) {
  erase();
  mc_print_title();
  mc_print_hints_n_time();
  mc_print_main_body();
  refresh();
}


bool tui_open(void) {
  screen_ready = initscr();
  if (!screen_ready) {
    warnx("initscr() failed");
    return false;
  }
  raw();
  noecho();
  // reset cache
  cached_title_ulen = -1;
  stat_title_len = -1;
  //
  if (run_opts.color)
    if (!has_colors())
      run_opts.color = false;
  //
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
  if (mtr_args[0])
    snprinte(screen_title, sizeof(screen_title), "%s %s %s", PACKAGE_NAME, mtr_args, dsthost);
  else
    snprinte(screen_title, sizeof(screen_title), "%s %s", PACKAGE_NAME, dsthost);
  if (screen_title[0])
    screen_title_ulen = ustrnlen(screen_title, COLS);
  //
  mc_init();
  tui_redraw();
  curs_set(0);
  return true;
}

void tui_confirm(void) {
  if (at_quit || !stdscr || !screen_ready)
    return;
  at_quit = true;
  int y = LINES - 1;
  move(y - 1, 0); clrtoeol();
  move(y,     0); clrtoeol();
  int len = ustrnlen(ANYQUIT_STR, COLS - 4) + 4;
  mvprintw(y - 1, (COLS - len) / 2, "%s ...", ANYQUIT_STR);
  flushinp();
  getch();
}

void tui_close(void) {
  if (stdscr && screen_ready) {
    endwin();
    screen_ready = false;
  }
}

inline void tui_clear(void) {
  tui_close();
  tui_open();
}

inline const char* tui_version(void) {
  return
#if   defined(HAVE_CURSES_VERSION)
  curses_version()
#elif defined(TUIKIND)
  TUIKIND
#else
  UNKNOWN_STR
#endif
  ;
}

