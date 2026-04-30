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
#  error No *curses header file given
#endif

#include "aux.h"
#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#ifdef WITH_MOUSE
#ifdef UNICODE
#define MENU_ICON "≡"
#endif
static bool moused;
#define MOUSE_ON  do { if (mouse_enabled) moused = true;  } while (0)
#define MOUSE_OFF do { if (mouse_enabled) moused = false; } while (0)
#else
#define MOUSE_ON  NOOP
#define MOUSE_OFF NOOP
#endif

#define MSEC_FMT "%.*f %s"

enum {
  INDENT_NUMB =    4, /* "NN. " */
  INDENT_HINT =   12,
  HOSTINFOMAX =   30,
  GETCH_BATCH =  100,
  LINEMAXLEN  = 1024,
};

enum {NDX_TITLE = 0, NDX_MENU, NDX_LABEL, NDX_WORK, NDX_STATUS, MAX_AREA_NDX};
typedef struct {
  WINDOW *win;
  int height; // not in use yet
} area_s;
static area_s area[MAX_AREA_NDX] = {
  [NDX_TITLE]  = {.height =  1},
  [NDX_MENU]   = {.height =  1},
  [NDX_LABEL]  = {.height =  2},
  [NDX_WORK]   = {.height = -5 /*sum others*/},
  [NDX_STATUS] = {.height =  1},
};

static bool stat_labels_redrawn; // if 0: stat_labels need redrawing

static char screen_title[NAMELEN]; // progname + arguments + destination
static uint screen_title_len;
static bool at_quit, screen_ready;

typedef struct {
  int screen, stat, chart;
} title_len_s;
static title_len_s titlelen;

#ifdef WITH_MOUSE
typedef struct { int x0, y0, x1, y1; } crd_s;
typedef struct { crd_s hint, quit; } item_crd_s;
static item_crd_s crd;
#endif

//

#ifdef WITH_MOUSE
void anygetch(WINDOW *win) {
  // skip buffered mouse clicks
  for (int i = 0; i < GETCH_BATCH; i++) {
    int ch = wgetch(win);
    if (ch != KEY_MOUSE) break;
  }
}
#else
#define anygetch wgetch
#endif

static size_t enter_smth(WINDOW *win, char *buf, size_t size, int x) NONNULL(1);
static size_t enter_smth(WINDOW *win, char *buf, size_t size, int x) {
  wmove(win, 0, x);
  int ch = 0, curs = curs_set(1);
  wrefresh(win);
  for (uint i = 0; ((ch = wgetch(win)) != '\n') && (i < size);) {
    waddch(win, (uint)ch | A_BOLD);
    wrefresh(win);
    buf[i++] = ch;
  }
  wmove(win, 0, 0);
  wclrtoeol(win);
  wrefresh(win);
  if (curs != ERR) curs_set(curs);
  return strnlen(buf, size - 1);
}

static void enter_stat_fields(WINDOW *win) NONNULL(1);
static void enter_stat_fields(WINDOW *win) {
  char fields[MAXFLD + 1] = {0};
  int ch = 0, curs = curs_set(1);
  for (uint i = 0; ((ch = wgetch(win)) != '\n') && (i < sizeof(fields));) {
    int nth = 0;
    for (; nth < stat_max; nth++) if (ch == stats[nth].key) {
      waddch(win, (uint)ch | A_BOLD);
      wrefresh(win);
      fields[i++] = ch;
      break;
    }
    if (nth >= stat_max) // beep on too long
      beep();
  }
  if (fields[0]) set_fld_active(fields);
  if (curs != ERR) curs_set(curs);
}

static void tui_get_int(WINDOW *win, int *val, int min, int max,
  const char *what, const char *hint) NONNULL(1);
static void tui_get_int(WINDOW *win, int *val, int min, int max,
  const char *what, const char *hint)
{
  MOUSE_OFF;
  mvwprintw(win, 0, 0, "%s: %d", what, *val);
  if (hint)
    mvwprintw(win, 1, 0, "-> %s", hint);
  int xpos = (what && what[0]) ? ustrnlen(what, getmaxx(win)) : 0;
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(win, entered, sizeof(entered), xpos + 2)) {
    char emsg[NAMELEN] = {0};
    int num = arg2int(0, entered, min, max, what, emsg, sizeof(emsg));
    if (emsg[0]) {
      wprintw(win, "%s. %s ...", emsg, ANYCONT_STR);
      wrefresh(win);
      anygetch(win);
    } else
      *val = num;
  }
  MOUSE_ON;
}

static void tui_key_h(WINDOW *win) NONNULL(1);
static void tui_key_h(WINDOW *win) { // help
  MOUSE_OFF;
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
    {.key =
#ifdef WITH_UNICODE
            "↑↓"
#endif
            "+-",         .hint = CMD_UD1_STR},
    {.key = PGUPDOWN_STR, .hint = CMD_UD5_STR},
    {.key = SPACE_STR,    .hint = CMD_SP_STR},
  };
  werase(win);
  int x = 2, y = 1;
  int maxx = getmaxx(win);
  mvwprintw(win, y++, 0, "%s:", COMMANDS_STR);
  for (uint i = 0; i < ARRAY_LEN(cmd); i++) {
    int pad = INDENT_HINT - ustrnlen(cmd[i].key, INDENT_HINT);
    const char *type = cmd[i].type == CH_INT ? CH_NUM_STR :
                       cmd[i].type == CH_STR ? CH_STR_STR : NULL;
    if (type) {
      pad -= ustrnlen(type, maxx) + 1;
      mvwprintw(win, y++, x, "%s %s%*s %s", cmd[i].key, type, (pad < 0) ? 0 : pad, "", cmd[i].hint);
    } else
      mvwprintw(win, y++, x, "%s%*s %s", cmd[i].key, (pad < 0) ? 0 : pad, "", cmd[i].hint);
  }
  mvwprintw(win, ++y, 0, "%s ...", ANYCONT_STR);
  wrefresh(win);
  anygetch(win);
  MOUSE_ON;
}

static void tui_key_b(WINDOW *win) NONNULL(1);
static void tui_key_b(WINDOW *win) { // bit pattern
  tui_get_int(win, &run_opts.pattern, -1, UINT8_MAX, BITPATT_STR, RANGENEG_STR);
  OPT_SUM(pattern);
  reset_pattern = true;
}

static void tui_key_c(WINDOW *win) NONNULL(1);
static void tui_key_c(WINDOW *win) { // set number of cycles
  MOUSE_OFF;
  mvwprintw(win, 0, 0, "%s (%s): %d", NCYCLES_STR, UNLIM0_STR, run_opts.cycles);
  int dx = 2;
  int maxc = getmaxx(win) / 2 - dx;
  int xpos = (maxc > 0) ? (ustrnlen(NCYCLES_STR, maxc) + dx) : 0;
  dx++; maxc--;
  xpos    += (maxc > 0) ? (ustrnlen(UNLIM0_STR,  maxc) + dx) : 0;
  //
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(win, entered, sizeof(entered), xpos)) {
    char emsg[NAMELEN] = {0};
    int num = arg2int(0, entered, 0, INT_MAX, NCYCLES_STR, emsg, sizeof(emsg));
    if (emsg[0]) {
      wprintw(win, "%s. %s ...", emsg, ANYCONT_STR);
      wrefresh(win);
      wgetch(win);
    } else {
      run_opts.cycles = num;
      OPT_SUM(cycles);
    }
  }
  MOUSE_ON;
}

static void tui_key_f(WINDOW *win) NONNULL(1);
static void tui_key_f(WINDOW *win) { // first ttl
  int minttl = run_opts.minttl;
  tui_get_int(win, &minttl, 1, run_opts.maxttl, MINTTL_STR, NULL);
  run_opts.minttl = minttl;
  OPT_SUM(minttl);
}

static void tui_key_i(WINDOW *win) NONNULL(1);
static void tui_key_i(WINDOW *win) { // interval
  tui_get_int(win, &run_opts.interval, 1, INT_MAX, GAPINSEC_STR, NULL);
  OPT_SUM(interval);
}

static void tui_key_m(WINDOW *win) NONNULL(1);
static void tui_key_m(WINDOW *win) { // max ttl
  int maxttl = run_opts.maxttl;
  tui_get_int(win, &maxttl, run_opts.minttl, MAXHOST - 1, MAXTTL_STR, NULL);
  run_opts.maxttl = maxttl;
  OPT_SUM(maxttl);
}

static void tui_key_o(WINDOW *win) NONNULL(1);
static void tui_key_o(WINDOW *win) { // set fields to display and their order
  MOUSE_OFF;
  mvwprintw(win, 0, 0, "%s: %s\n\n", FIELDS_STR, fld_active);
  for (int i = 0; i < stat_max; i++) if (stats[i].hint)
    wprintw(win, "  %c: %s\n", stats[i].key, stats[i].hint);
  int maxc = getmaxx(win) - 2;
  wmove(win, 0, (maxc > 0) ? (ustrnlen(FIELDS_STR, maxc) + 2) : 0);
  wrefresh(win);
  enter_stat_fields(win);
  MOUSE_ON;
}

#ifdef IP_TOS
static void tui_key_Q(WINDOW *win) NONNULL(1);
static void tui_key_Q(WINDOW *win) { // set QoS
  MOUSE_OFF;
#if defined(ENABLE_IPV6) && !defined(IPV6_TCLASS)
  if (af == AF_INET6) {
    mvwprintw(win, 0, 0, "%s", TCLASS6_ERR);
    mvwprintw(win, 1, 0, "-> %s ...", ANYCONT_STR);
    anygetch(win);
  } else
#endif
  { int qos = run_opts.qos;
    tui_get_int(win, &qos, 0, UINT8_MAX, QOSTOS_STR, TOS_HINT_STR);
    run_opts.qos = qos;
    OPT_SUM(qos);
  }
  MOUSE_ON;
}
#endif

static void tui_key_s(WINDOW *win) NONNULL(1);
static void tui_key_s(WINDOW *win) { // set payload size
  MOUSE_OFF;
  mvwprintw(win, 0, 0, "%s: %d", PSIZE_CHNG_STR, run_opts.size);
  const int max = MAXPACKET - MINPACKET;
  mvwprintw(win, 1, 0, "-> %s[%d,%d], %s", RANGE_STR, -max, max, NEG4RND_STR);
  char entered[MAXFLD + 1] = {0};
  int xpos = ustrnlen(PSIZE_CHNG_STR, getmaxx(win) - 2) + 2;
  if (enter_smth(win, entered, sizeof(entered), xpos)) {
    char emsg[NAMELEN] = {0};
    int num = arg2int(0, entered, -max, max, PSIZE_STR, emsg, sizeof(emsg));
    if (emsg[0]) {
      wprintw(win, "%s. %s ...", emsg, ANYCONT_STR);
      wrefresh(win);
      anygetch(win);
    } else {
      run_opts.size = num;
      OPT_SUM(size);
      reset_pldsize = true;
    }
  }
  MOUSE_ON;
}

// map: char to action
static key_action_t action_map[UINT8_MAX] =  {
  ['+'] = ActionLineDown,
  ['-'] = ActionLineUp,
  ['d'] = ActionDisplay,
#ifdef WITH_MPLS
  ['e'] = ActionMPLS,
#endif
  ['j'] = ActionJitter,
#ifdef WITH_IPINFO
  ['l'] = ActionAS,
  ['L'] = ActionII,
#endif
#ifdef ENABLE_DNS
  ['n'] = ActionDNS,
#endif
  [' '] = ActionPauseResume,
  ['p'] = ActionPauseResume,
  [3/*^C*/]   = ActionQuit,
//[27/*Esc*/] = ActionQuit,
  ['q'] = ActionQuit,
  ['r'] = ActionReset,
  ['t'] = ActionTCP,
  ['u'] = ActionUDP,
  ['x'] = ActionCache,
};

typedef void (*tui_key_fn)(WINDOW *win);

// map: local actions
static tui_key_fn actfn_map[UINT8_MAX] =  {
  ['?'] = tui_key_h,
  ['h'] = tui_key_h, // help
  ['b'] = tui_key_b, // bit pattern
  ['c'] = tui_key_c, // number of cycles
  ['f'] = tui_key_f, // first ttl
  ['i'] = tui_key_i, // interval
  ['m'] = tui_key_m, // max ttl
  ['o'] = tui_key_o, // fields to display
#ifdef IP_TOS
  ['Q'] = tui_key_Q, // qos
#endif
  ['s'] = tui_key_s, // payload size
};

static inline void reset_actkey_flags(int ch) {
  switch (ch) {
    case  3 : // ^C
//  case  27: // Esc
    case 'q':
      at_quit = true;
      break;
    case '?':
    case 'h':
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
    case 'o': // fields to display and their order
    case ' ':
    case 'p': // ActionPauseResume;
#ifdef IP_TOS
    case 'Q': // qos
#endif
    case 's': // payload size
    case 't': // ActionTCP;
    case 'u': // ActionUDP;
    case 'x': // ActionCache;
      stat_labels_redrawn = false;
      titlelen.screen = -1;
      break;
    default: break;
  }
}

#define CRD_ENCLOSE(crd) (                       \
  ((crd).x0 <= event.x) && (event.x <= (crd).x1) \
  &&                                             \
  ((crd).y0 <= event.y) && (event.y <= (crd).y1) \
)
key_action_t tui_keyaction(void) {
  WINDOW *win = area[NDX_LABEL].win; if (!win)  return ActionNone;
  int ch = wgetch(win); if (!ch || (ch == ERR)) return ActionNone;
#ifdef KEY_RESIZE
  // skip resize keys
  if (ch == KEY_RESIZE) { // cleanup by batch
    for (int i = 0; (ch == KEY_RESIZE) && (i < GETCH_BATCH); i++)
      ch = wgetch(win);
    if (ch == KEY_RESIZE) // otherwise flush
      flushinp();
  }
#endif
#ifdef WITH_MOUSE
  // map mouse events to keys
  if (moused && ch == KEY_MOUSE) {
    MEVENT event = {0};
    if (getmouse(&event) == OK
      // && (event.bstate & BUTTON1_CLICKED) /*already filtered*/
    ) {
      if      (CRD_ENCLOSE(crd.hint)) ch = 'h';
      else if (CRD_ENCLOSE(crd.quit)) ch = 'q';
    }
  }
#endif
  reset_actkey_flags(ch);
//
  key_action_t action = ActionNone /*0*/;
  if (ch < UINT8_MAX) { // 8bit char
    tui_key_fn fn = actfn_map[ch];
    if (fn) // handle it here
      fn(fn == tui_key_h ? stdscr : win);
    else    // or somewhere else
      action = action_map[ch];
  } else switch (ch) {  // more than 8 bits
    case KEY_UP:
      action = ActionLineDown;
      break;
    case KEY_DOWN:
      action = ActionLineUp;
      break;
    case KEY_PPAGE: // PageUp
      action = ActionPageDown;
      break;
    case KEY_NPAGE: // PageDown
      action = ActionPageUp;
      break;
    default: break;
  }
  return action;
}

#ifdef WITH_MPLS
static int printw_mpls(WINDOW *win, const mpls_data_t *m) NONNULL(1, 2);
static int printw_mpls(WINDOW *win, const mpls_data_t *m) {
  for (int i = 0; i < m->n; i++) {
    wprintw(win, "%s", mpls2str(&(m->label[i]), 4));
    if (wmove(win, getcury(win) + 1, 0) == ERR)
      return ERR;
  }
  return OK;
}
#endif

static void printw_addr(WINDOW *win, int at, int ndx) NONNULL(1);
static void printw_addr(WINDOW *win, int at, int ndx) {
  t_ipaddr *addr = &IP_AT_NDX(at, ndx);
#ifdef WITH_IPINFO
  if (ipinfo_ready()) {
    char info[NAMELEN] = {0};
    ipinfo_data_fix(info, sizeof(info), at, ndx);
    if (info[0])
      wprintw(win, "%s", info);
  }
#endif
  bool down = !host[at].up;
  if (down)
    wattron(win, A_BOLD);
#ifdef ENABLE_DNS
  const char *name = dns_ptr_lookup(at, ndx);
  if (name) {
    wprintw(win, "%s", name);
    if (run_opts.both)
      wprintw(win, " (%s)", strlongip(addr));
  } else
#endif
  { wprintw(win, "%s", strlongip(addr)); }
  if (down)
    wattroff(win, A_BOLD);
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

static inline void print_statline(WINDOW *win, int at, const t_stat *stat) NONNULL(1);
static inline void print_statline(WINDOW *win, int at, const t_stat *stat) {
  // if there's no replies, show only packet counters
  const char *str = (host[at].recv || strchr("LDRS", stat->key)) ? net_elem(at, stat->key) : "";
  wprintw(win, "%*s", stat->min, str ? str : "");
}

static int print_stat(WINDOW *win, int at, int y, int x, int max) NONNULL(1);
static int print_stat(WINDOW *win, int at, int y, int x, int max) { // statistics
  if (wmove(win, y, x) == ERR) return ERR;
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (stat) print_statline(win, at, stat); else break;
  }
  if (run_opts.audible || run_opts.visible)
    seal_n_bell(at, max);
  return wmove(win, y + 1, 0);
}

static void print_addr_extra(WINDOW *win, int at) NONNULL(1);
static void print_addr_extra(WINDOW *win, int at) { // mpls + multipath
  for (int ndx = 0; ndx < MAXPATH; ndx++) {  // multipath
    if (ndx == host[at].current)
      continue; // because already printed
    t_ipaddr *addr = &IP_AT_NDX(at, ndx);
    if (!addr_exist(addr))
      break;
    wprintw(win, "    ");
    printw_addr(win, at, ndx);
    if (wmove(win, getcury(win) + 1, 0) == ERR)
      break;
#ifdef WITH_MPLS
    if (run_opts.mpls)
      if (printw_mpls(win, &MPLS_AT_NDX(at, ndx)) == ERR)
        break;
#endif
  }
}

static void print_hops(WINDOW *win, int statx) NONNULL(1);
static void print_hops(WINDOW *win, int statx) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    int y = getcury(win);
    if (wmove(win, y, 0) == ERR)
      break;
    wprintw(win, AT_FMT " ", at + 1);
    t_ipaddr *addr = &CURRENT_IP(at);
    if (addr_exist(addr)) {
      printw_addr(win, at, host[at].current);
      if (print_stat(win, at, y, statx, max) == ERR)
        break;
#ifdef WITH_MPLS
      if (run_opts.mpls)
        printw_mpls(win, &CURRENT_MPLS(at));
#endif
      print_addr_extra(win, at);
    } else {
      wprintw(win, "%s", UNKN_ITEM);
      if (wmove(win, y + 1, 0) == ERR)
        break;
      if ((at < (max - 1)) && (print_stat(win, at, y, statx, max) == ERR))
        break;
    }
  }
  wmove(win, 0, 0);
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
    return map[0]; /* unsent ' ' */ \
  if ((saved_int == CT_UNKN) || (saved_int == CT_SEAL)) \
    return map[1]; /* no response '?' */ \
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
static cchar_t* mc_saved_cc(int saved_int) {
  NA_MAP(&map_na3);
  int num = run_opts.color ? NUM_FACTORS3 : (NUM_FACTORS3_MONO + 1);
  for (int i = 0; i < num; i++)
    if (saved_int <= scale3[i])
      return &map3[i];
  return &map_na3[2]; // UNKN
}
#endif

static void histoaddr(WINDOW *win, int at, int max, int y, int x, int cols) NONNULL(1);
static void histoaddr(WINDOW *win, int at, int max, int y, int x, int cols) {
  t_ipaddr *addr = &CURRENT_IP(at);
  if (addr_exist(addr)) {
    if (!host[at].up)
      wattron(win, A_BOLD);
#ifdef WITH_IPINFO
    if (ipinfo_ready()) {
      char info[NAMELEN] = {0};
      ipinfo_data_fix(info, sizeof(info), at, host[at].current);
      if (info[0])
        wprintw(win, "%s", info);
    }
#endif
#ifdef ENABLE_DNS
    const char *name = dns_ptr_lookup(at, host[at].current);
    wprintw(win, "%s", name ? name : strlongip(addr));
#else
    wprintw(win, "%s", strlongip(addr));
#endif
    if (!host[at].up)
      wattroff(win, A_BOLD);
    mvwprintw(win, y, x, " ");
#ifdef WITH_UNICODE
    if (chart_mode == 3)
      for (int i = SAVED_PINGS - cols; i < SAVED_PINGS; i++)
        wadd_wch(win, mc_saved_cc(host[at].saved[i]));
    else
#endif
      for (int i = SAVED_PINGS - cols; i < SAVED_PINGS; i++)
        waddch(win, get_saved_ch(host[at].saved[i]));
    if (run_opts.audible || run_opts.visible)
      seal_n_bell(at, max);
  } else wprintw(win, "%s", UNKN_ITEM);
}

static void histogram(WINDOW *win, int x, int cols) NONNULL(1);
static void histogram(WINDOW *win, int x, int cols) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    int y = getcury(win);
    if (wmove(win, y, 0) == ERR) break;
    wprintw(win, AT_FMT " ", at + 1);
    histoaddr(win, at, max, y, x, cols);
    if (wmove(win, y + 1, 0) == ERR) break;
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

static inline int mc_fit_posx(int pos, int len, int maxx) {
  int lcols = maxx - 1 - len;
  return (pos < lcols) ? pos : lcols;
}

static void display_main_labels(WINDOW *win, int indent) NONNULL(1);
static void display_main_labels(WINDOW *win, int indent) {
  if (wmove(win, 1, indent) == ERR) return;
  bool custom = is_custom_fld();
  int maxx = getmaxx(win);
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    if (!i || (i == 3)) { // add subtitles
      int curx = getcurx(win);
      int dx   = (stat->min > stat->len) ? (stat->min - stat->len) : 1;
      int pos  = curx + dx;
      if (!i && custom) {
        int ufl = (maxx > 2) ? ustrnlen(USR_FIELDS_STR, maxx - 2) : 0;
        int len = ufl + 2 + strnlen(fld_active, MAXFLD);
        mvwprintw(win, 0, mc_fit_posx(pos, len, maxx), "%s: %s", USR_FIELDS_STR, fld_active);
      } else if (!custom) {
        const char *sub = i ? PINGS_STR : PACKETS_STR;
        int len = ustrnlen(sub, maxx);
        mvwprintw(win, 0, mc_fit_posx(pos, len, maxx), "%s", i ? PINGS_STR : PACKETS_STR);
      }
      wmove(win, 1, curx);
    }
    wprintw(win, "%*s%s",
      (stat->min > stat->len) ? (stat->min - stat->len) : 1, "",
      stat->name ? stat->name : "");
  }
}

#ifdef WITH_UNICODE
static void mc_print_scale3(WINDOW *win, int min, int max, int step) NONNULL(1);
static void mc_print_scale3(WINDOW *win, int min, int max, int step) {
  for (int i = min; i < max; i += step) {
    waddstr(win, "  ");
    wadd_wch(win, &map3[i]);
    if (scale3[i] > 0) {
      LENVALMIL(scale3[i]);
      wprintw(win, ":" MSEC_FMT, _l, _v, MSEC_STR);
    }
  }
  waddstr(win, "  ");
  wadd_wch(win, &map3[max]);
}
#endif

static inline int map2ch(int ndx) { return map2[ndx] & A_CHARTEXT; }

static void print_scale(WINDOW *win) NONNULL(1);
static void print_scale(WINDOW *win) {
  wattron(win, A_BOLD);
  wprintw(win, "%s:", SCALE_STR);
  wattroff(win, A_BOLD);
  if (chart_mode == 1) {
    waddstr(win, "  ");
    waddch(win, map1[0] | A_BOLD);
    LENVALMIL(scale2[NUM_FACTORS2 - 2]);
    wprintw(win, " %s " MSEC_FMT "   ", LESSTHAN_STR, _l, _v, MSEC_STR);
    waddch(win, map1[1] | (run_opts.color ? 0 : A_BOLD));
    wprintw(win, " %s " MSEC_FMT "   ", MORETHAN_STR, _l, _v, MSEC_STR);
    waddch(win, '?' | (run_opts.color ? (map2[NUM_FACTORS2 - 1] & A_ATTRIBUTES) : A_BOLD));
    wprintw(win, " %s", UNKNOWN_STR);
  } else if (chart_mode == 2) {
    if (run_opts.color) {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        waddstr(win, "  ");
        waddch(win, map2[i]);
        if (scale2[i] > 0) {
          LENVALMIL(scale2[i]);
          wprintw(win, ":" MSEC_FMT, _l, _v, MSEC_STR);
        }
      }
      waddstr(win, "  ");
      waddch(win, map2[NUM_FACTORS2 - 1]);
    } else {
      for (int i = 0; i < NUM_FACTORS2 - 1; i++) {
        if (scale2[i] > 0) {
          LENVALMIL(scale2[i]);
          wprintw(win, "  %c:" MSEC_FMT, map2ch(i), _l, _v, MSEC_STR);
        }
      }
      wprintw(win, "  %c", map2ch(NUM_FACTORS2 - 1));
    }
  }
#ifdef WITH_UNICODE
  else if (chart_mode == 3) {
    if (run_opts.color)
      mc_print_scale3(win, 1, NUM_FACTORS3 - 1,  2);
    else
      mc_print_scale3(win, 0, NUM_FACTORS3_MONO, 1);
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
  if (inc > 0) len += inc;           \
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

static void display_charts(WINDOW *label, WINDOW *work) NONNULL(1, 2);
static void display_charts(WINDOW *label, WINDOW *work) {
#define CHART_COLS(mx) (((mx) <= (SAVED_PINGS + dx)) ? ((mx) - dx) : SAVED_PINGS)
  int dx = HOSTINFOMAX;
#ifdef WITH_IPINFO
  if (ipinfo_ready()) dx += ipinfo_width();
#endif
  //
  // title part
  werase(label);
  static char chart_title[256];
  if (titlelen.chart < 0) {
    memset(chart_title, 0, sizeof(chart_title));
    int maxx = getmaxx(label);
    int len = snprinte(chart_title, sizeof(chart_title),
      "%s: %d %s", HISTOGRAM_STR, CHART_COLS(maxx), HCOLS_STR);
    if (len >= 0)
      titlelen.chart = ustrnlen(chart_title, getmaxx(label));
  }
  if (titlelen.chart > 0) {
    int x = (getmaxx(label) - titlelen.chart) / 2;
    mvwprintw(label, 0, (x > 0) ? x : 0, "%s", chart_title);
  }
  wrefresh(label);
  //
  // chart part
  werase(work);
  if (wmove(work, 0, 0) != ERR) {
    wattroff(work, A_BOLD);
    dmode_scale_map();
    int maxx = getmaxx(work);
    histogram(work, dx - 2 /* right_pad(1) + 1 */, CHART_COLS(maxx));
    if (wmove(work, getcury(work) + 1, 0) != ERR)
      print_scale(work);
  }
  wrefresh(work);
#undef CHART_COLS
}

static int redraw_stat_labels(WINDOW *win, int indent) NONNULL(1);
static int redraw_stat_labels(WINDOW *win, int indent) {
  werase(win);
  wattron(win, A_BOLD);
#ifdef WITH_IPINFO
  if (ipinfo_ready()) {
    char info[NAMELEN] = {0};
    ipinfo_head_fix(info, sizeof(info));
    if (info[0])
      mvwprintw(win, 1, indent, "%s", info);
    indent += ipinfo_width(); // indent: "NN. " + IPINFO
  }
#endif
  mvwprintw(win, 1, indent, "%s", HOST_STR);
  if (titlelen.stat < 0)
    titlelen.stat = get_stat_title_len();
  indent = getmaxx(win) - (titlelen.stat + 1);
  if (indent < 0) indent = 0;
  display_main_labels(win, indent);
  wattroff(win, A_BOLD);
  wrefresh(win);
  return indent;
}

static void display_stat_area(WINDOW *win, int stat_indent) NONNULL(1);
static void display_stat_area(WINDOW *win, int stat_indent) {
  werase(win);
  print_hops(win, stat_indent);
  wrefresh(win);
}

static void display_title(WINDOW *win) NONNULL(1);
static void display_title(WINDOW *win) {
  static char title_cache[LINEMAXLEN];
  werase(win);
  if (titlelen.screen < 0) { // generate title and cache it
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
      titlelen.screen = ustrnlen(title_cache, getmaxx(win));
  }
  //
  const char *title = NULL;
  if (titlelen.screen > 0)
    title = title_cache;
  else {
    title = screen_title;
    titlelen.screen = screen_title_len;
  }
  if (title && *title) {
    int x = (getmaxx(win) - titlelen.screen) / 2;
    mvwprintw(win, 0, (x > 0) ? x : 0, "%s", title);
  }
  wrefresh(win);
}

#define PRINT_MENUITEM(ch, fmt, txt) do {            \
  wattron (win, A_BOLD); waddch(win, (ch));          \
  wattroff(win, A_BOLD); wprintw(win, (fmt), (txt)); \
} while (0)
#define PRINT_MENUKEEP(ch, fmt, txt, crd) do {       \
  (crd).x0 = dx + getcurx(win);                      \
  (crd).y0 = dy + getcury(win);                      \
  PRINT_MENUITEM((ch), (fmt), (txt));                \
  (crd).x1 = dx + getcurx(win) - 1;                  \
  (crd).y1 = dx + getcurx(win) - 1;                  \
} while (0)

static void display_menuline(WINDOW *win) NONNULL(1);
static void display_menuline(WINDOW *win) {
  werase(win);
  mvwprintw(win, 0, 0, "%s: ", MENU_STR);
  //
#ifdef WITH_MOUSE
  { int dx = getbegx(win), dy = getbegy(win);
    PRINT_MENUKEEP('h', "%s ", _HINTS_STR, crd.hint);
    PRINT_MENUKEEP('q', "%s" , _QUIT_STR , crd.quit); }
#else
  PRINT_MENUITEM('h', "%s ", _HINTS_STR);
  PRINT_MENUITEM('q', "%s", _QUIT_STR);
#endif
  char buff[LINEMAXLEN] = {0};
  // source host
  int len = snprinte(buff, sizeof(buff), "%.*s", (int)strnlen(srchost, getmaxx(win) / 2), srchost);
  if (len < 0)
    return;
  // timestamp (note: not mandatory)
  char str[64] = {0};
  const char *date = datetime(time(NULL), str, sizeof(str));
  if (date && date[0])
    snprinte(buff + len, sizeof(buff) - len, ": %s", date);
  //
  if ((len > 0) && buff[0]) // rigth aligned
    mvwaddstr(win, 0, getmaxx(win) - ustrnlen(buff, sizeof(buff)) - 1, buff);
  wrefresh(win);
}

static inline void display_mainbody(WINDOW *label, WINDOW *work) NONNULL(1, 2);
static inline void display_mainbody(WINDOW *label, WINDOW *work) {
  if (chart_mode)
    display_charts(label, work);
  else {
    static int stat_indent;
    if (!(stat_indent && stat_labels_redrawn)) {
      stat_indent = redraw_stat_labels(label, INDENT_NUMB);
      if (!stat_labels_redrawn)
        stat_labels_redrawn = true;
    }
    display_stat_area(work, stat_indent);
  }
}

static WINDOW* create_area(int h, int *y) NONNULL(2);
static WINDOW* create_area(int h, int *y) {
  WINDOW *win = newwin(h, 0/*i.e.max*/, *y, 0);
  *y += h;
  if (win) {
    wrefresh(win);
    keypad(win, TRUE);
  }
  return win;
}

static void free_areas(void) {
  for (uint i = 0; i < ARRAY_LEN(area); i++) if (area[i].win) {
    delwin(area[i].win);
    area[i].win = NULL;
  }
}

static bool init_areas(void) {
  // reset cached titles
  titlelen = (title_len_s){.screen = -1, .stat = -1, .chart = -1};
  // create areas
  free_areas();
  int y = 0;
  if ((area[NDX_TITLE].win = create_area(1, &y)))
    if ((area[NDX_MENU].win = create_area(1, &y)))
      if ((area[NDX_LABEL].win = create_area(2, &y))) {
//      int h = LINES - (y + 1);
        int h = LINES - y;
        if ((area[NDX_WORK].win = create_area(h > 0 ? h : 1, &y)))
//        if ((area[NDX_STATUS].win = create_area(1, &y)))
          return true;
      }
  return false;
}

void tui_redraw(void) {
  static int my_cols = -1, my_lines = -1;
  if ((my_cols != COLS) || (my_lines != LINES)) {
    if (init_areas()) {
      my_cols  = COLS;
      my_lines = LINES;
      // reset caches, redraw labels
      titlelen = (title_len_s){.screen = -1, .stat = -1, .chart = -1};
      stat_labels_redrawn = false;
   } else { // something wrong
      erase();
      printw("TUI init areas: failed");
      refresh();
      return;
    }
  }
  display_title(area[NDX_TITLE].win);
  display_menuline(area[NDX_MENU].win);
  display_mainbody(area[NDX_LABEL].win, area[NDX_WORK].win);
}

bool tui_open(void) {
  screen_ready = initscr();
  if (!screen_ready) {
    warnx("TUI initscr() failed");
    return false;
  }
  raw();
  noecho();
  keypad(stdscr, TRUE);
  if (!init_areas()) return false;
#ifdef WITH_MOUSE
  if (mouse_enabled) {
    mousemask(BUTTON1_CLICKED | REPORT_MOUSE_POSITION, NULL);
    MOUSE_ON;
  }
#endif
  refresh();
  //
  // reset cached titles
  titlelen = (title_len_s){.screen = -1, .stat = -1, .chart = -1};
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
  screen_title_len = screen_title[0] ? ustrnlen(screen_title, getmaxx(area[NDX_TITLE].win)) : 0;
  //
  mc_init();
  tui_redraw();
  curs_set(0);
  return true;
}

void tui_confirm(void) {
  WINDOW *win = area[NDX_WORK].win;
  if (at_quit || !win || !screen_ready)
    return;
  at_quit = true;
  int y = getmaxy(win) - 2;
  wmove(win, y++, 0); wclrtoeol(win);
  wmove(win, y--, 0); wclrtoeol(win);
  int maxx = getmaxx(win);
  int len = (maxx > 4) ? ustrnlen(ANYQUIT_STR, maxx - 4) + 4 : maxx;
  mvwprintw(win, y, (maxx - len) / 2, "%s", ANYQUIT_STR);
  waddstr(win, " ...");
  flushinp();
  anygetch(win);
}

void tui_close(void) {
  MOUSE_OFF;
  if (stdscr && screen_ready) {
    free_areas();
    endwin();
    screen_ready = false;
  }
}

void tui_reset(void) {
  tui_close();
  tui_open();
}

void tui_clear(void) {
  erase();
  refresh();
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

