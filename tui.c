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

#if defined(LOG_TUI) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_TUI) && defined(LOGMOD)
#undef LOGMOD
#endif

#include "tui.h"
#include "chart.h"
#include "nls.h"
#include "aux.h"
#include "net.h"

#ifdef ENABLE_DNS
#include "dns.h"
#endif

#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#ifdef WITH_MOUSE
bool mouse_enabled;  // -0 option: disabled
                     // -1 option: enabled (can be disabled with -M option)

#define MENU_ICON_UTF8  " ≡ "
#define MENU_ICON_ASCII " = "
#define QUIT_ICON_UTF8  " ✕ " // ✕ ✖ x 🗙 ╳
#define QUIT_ICON_ASCII " x "
//
static const char *menu_icon = MENU_ICON_ASCII;
static const char *quit_icon = QUIT_ICON_ASCII;
static int /*menu_icon_len,*/ quit_icon_len;
//
static bool mouse_on;
#define MOUSE_ON  do { if (mouse_enabled) mouse_on = true;  } while (0)
#define MOUSE_OFF do { if (mouse_enabled) mouse_on = false; } while (0)
//
typedef struct {
  int x0, y0, x1, y1;
} crd_s;
//
typedef struct {
  crd_s menu, quit;
} crd_topbar_s;
static crd_topbar_s crd_topbar;
//
typedef struct {
  crd_s jttr;
  crd_s chart;
#ifdef ENABLE_DNS
  crd_s dns;
#endif
#ifdef WITH_IPINFO
  crd_s asn;
  crd_s info;
#endif
#ifdef WITH_MPLS
  crd_s mpls;
#endif
} crd_status_s;
static crd_status_s crd_status;
#else
#define MOUSE_ON  NOOP
#define MOUSE_OFF NOOP
#endif

//#define VUSLASH "│"
//#define VASLASH '|'
//#define HOLLOW_CIRCLE "⭘"
//#define  SOLID_CIRCLE "⬤"
//#define POWER_OFF "⭘"
//#define POWER_ON  "⏽"

static uint display_offset; // used with: PageUp, PageDown, LineUp, LinedDown

enum {
  LINES_PER_PAGE = 5,
  INDENT_HINT =   12,
  HOSTINFOMAX =   30,
  GETCH_BATCH =  100,
  LINEMAXLEN  = 1024,
};

enum {NDX_TOP = 0, NDX_STATUS, NDX_LABEL, NDX_WORK};
typedef struct {
  WINDOW *win;
  int height; // not in use yet
} area_s;

static area_s area[] = {
  [NDX_TOP]    = {.height =  1},
  [NDX_STATUS] = {.height =  1},
  [NDX_LABEL]  = {.height =  2},
  [NDX_WORK]   = {.height = -4 /*sum others*/},
};
static int area_old_order[ARRAY_LEN(area)] = {NDX_TOP, NDX_STATUS, NDX_LABEL, NDX_WORK};
static int area_new_order[ARRAY_LEN(area)] = {NDX_TOP, NDX_LABEL, NDX_WORK, NDX_STATUS};
static char* (*tui_datetime)(time_t at, size_t size, char buff[size]) NONNULL(3)
  = datetime_c;

typedef struct {
  bool top, labels, chart_title, field_status;
} redrawn_s;
static redrawn_s redrawn; // need redrawing unless true

static char screen_title[NAMELEN]; // progname + arguments + destination
static uint screen_title_len;
static bool at_quit, screen_ready;

typedef struct {
  int screen, stat, chart;
} title_len_s;
static title_len_s titlelen;

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
  if (curs != ERR)
    curs_set(curs);
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
  if (fields[0])
    set_fld_active(fields);
  if (curs != ERR)
    curs_set(curs);
}

static void tui_msgcont(WINDOW *win, const char *msg) NONNULL(1, 2);
static void tui_msgcont(WINDOW *win, const char *msg) {
  waddstr(win, msg);
  waddstr(win, ". ");
  waddstr(win, ANYCONT_STR);
  waddstr(win, " ...");
  wrefresh(win);
  wgetch(win);
}

static void tui_get_int(WINDOW *win, int *val, int min, int max,
  const char *what, const char *hint) NONNULL(1);
static void tui_get_int(WINDOW *win, int *val, int min, int max,
  const char *what, const char *hint)
{
  MOUSE_OFF;
  wclear(win);
  mvwaddstr(win, 0, 0, what);
  wprintw(win, ": %d", *val);
  if (hint) {
    mvwaddstr(win, 1, 0, "-> ");
    waddstr(win, hint);
  }
  int xpos = (what && what[0]) ? ustrnlen(what, getmaxx(win)) : 0;
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(win, entered, sizeof(entered), xpos + 2)) {
    char error[NAMELEN] = {0};
    int num = arg2int(0, entered, min, max, what, error, sizeof(error));
    if (error[0])
      tui_msgcont(win, error);
    else
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
#ifdef WITH_IPINFO
    {.key = "y", .hint = CMD_Y_STR},
#endif
    {.key =
#ifdef WITH_UNICODE
            utf_compat ? "↑↓+-" :
#endif
            "+-",         .hint = CMD_UD1_STR},
    {.key = PGUPDOWN_STR, .hint = CMD_UD5_STR},
    {.key = SPACE_STR,    .hint = CMD_SP_STR},
  };
  werase(win);
  int x = 2, y = 1;
  int maxx = getmaxx(win);
  mvwaddstr(win, y++, 0, COMMANDS_STR);
  waddch(win, ':');
  for (uint i = 0; i < ARRAY_LEN(cmd); i++) {
    int dx = INDENT_HINT - ustrnlen(cmd[i].key, INDENT_HINT);
    const char *type = cmd[i].type == CH_INT ? CH_NUM_STR :
                       cmd[i].type == CH_STR ? CH_STR_STR : NULL;
    mvwaddstr(win, y, x,cmd[i].key);
    if (type) {
      waddch(win, ' ');
      waddstr(win, type);
      dx -= ustrnlen(type, maxx) + 1;
    }
    wprintw(win, "%*s ", (dx < 0) ? 0 : dx, "");
    waddstr(win, cmd[i].hint);
    y++;
  }
  mvwaddstr(win, ++y, 0, ANYCONT_STR);
  waddstr(win, " ...");
  wrefresh(win);
  wgetch(win);
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
  mvwaddstr(win, 0, 0, NCYCLES_STR);
  waddstr(win, " (");
  waddstr(win, UNLIM0_STR);
  wprintw(win, "): %d", run_opts.cycles);
  int dx = 2;
  int maxc = getmaxx(win) / 2 - dx;
  int xpos = (maxc > 0) ? (ustrnlen(NCYCLES_STR, maxc) + dx) : 0;
  dx++; maxc--;
  xpos    += (maxc > 0) ? (ustrnlen(UNLIM0_STR,  maxc) + dx) : 0;
  //
  char entered[MAXFLD + 1] = {0};
  if (enter_smth(win, entered, sizeof(entered), xpos)) {
    char error[NAMELEN] = {0};
    int num = arg2int(0, entered, 0, INT_MAX, NCYCLES_STR, error, sizeof(error));
    if (error[0])
      tui_msgcont(win, error);
    else {
      run_opts.cycles = num;
      OPT_SUM(cycles);
    }
  }
  MOUSE_ON;
}

static void tui_key_d(WINDOW *win UNUSED) { // display modes (charts)
  chart_range_loop();
  tui_redraw();
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

static inline void tui_key_o_hints(int x0, int y0) {
  int lines = 0;
  for (int i = 0; i < stat_max; i++)
    if (stats[i].hint)
      lines++;
  WINDOW *aux = (lines > 0) ? newwin(lines, 0, y0, x0) : NULL;
  if (aux) {
    wclear(aux);
    for (int i = 0, y = 0; i < stat_max; i++) if (stats[i].hint) {
      mvwaddstr(aux, y++, 0, "  ");
      waddch(aux, stats[i].key);
      waddstr(aux, ": ");
      waddstr(aux, stats[i].hint);
    }
    wrefresh(aux);
    delwin(aux);
  }
}

static void tui_key_o(WINDOW *win) NONNULL(1);
static void tui_key_o(WINDOW *win) { // set fields to display and their order
  MOUSE_OFF;
  tui_key_o_hints(getbegx(win), getbegy(win) + getmaxy(win));
  wclear(win);
  mvwaddstr(win, 0, 0, FIELDS_STR);
  waddstr(win, ": ");
  waddstr(win, fld_active);
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
  if (af == AF_INET6)
    tui_msgcont(win, TCLASS6_ERR);
  else
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
  wclear(win);
  int x = 0, y = 0;
  mvwaddstr(win, y, x, PSIZE_CHNG_STR);
  wprintw(win, ": %d", run_opts.size);
  const int max = MAXPACKET - MINPACKET;
  mvwaddstr(win, ++y, x, "-> ");
  waddstr(win, RANGE_STR);
  wprintw(win, "[%d,%d], ", -max, max);
  waddstr(win, NEG4RND_STR);
  char entered[MAXFLD + 1] = {0};
  int xpos = ustrnlen(PSIZE_CHNG_STR, getmaxx(win) - 2) + 2;
  wrefresh(win);
  if (enter_smth(win, entered, sizeof(entered), xpos)) {
    char error[NAMELEN] = {0};
    int num = arg2int(0, entered, -max, max, PSIZE_STR, error, sizeof(error));
    if (error[0])
      tui_msgcont(win, error);
    else {
      run_opts.size = num;
      OPT_SUM(size);
      reset_pldsize = true;
    }
  }
  MOUSE_ON;
}

static void linedown(uint lines) {
  display_offset += lines;
  int hops = net_max() - net_min();
  if ((hops > 0) && (display_offset >= (uint)hops))
    display_offset = hops - 1;
}
static void lineup(uint lines) {
  if (display_offset > lines)
    display_offset -= lines;
  else
    display_offset = 0;
}

static void tui_key_plus(WINDOW *win UNUSED) {
  linedown(1);
  LOGMSG("line %s", "down");
}

static void tui_key_minus(WINDOW *win UNUSED) {
 lineup(1);
 LOGMSG("line %s", "up");
}

// map: char to action
static key_action_t action_map[UINT8_MAX] =  {
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
#ifdef WITH_IPINFO
  ['y'] = ActionMultiII,
#endif
};

typedef void (*tui_key_fn)(WINDOW *win) NONNULL(1);

// map: local actions
static tui_key_fn actfn_map[UINT8_MAX] =  {
  ['?'] = tui_key_h,
  ['h'] = tui_key_h, // help
  ['b'] = tui_key_b, // bit pattern
  ['c'] = tui_key_c, // number of cycles
  ['d'] = tui_key_d, // display modes (charts)
  ['f'] = tui_key_f, // first ttl
  ['i'] = tui_key_i, // interval
  ['m'] = tui_key_m, // max ttl
  ['o'] = tui_key_o, // fields to display
#ifdef IP_TOS
  ['Q'] = tui_key_Q, // qos
#endif
  ['s'] = tui_key_s, // payload size
  ['+'] = tui_key_plus,  // line down
  ['-'] = tui_key_minus, // line up
};

static inline void require_redraw(void) {
  memset(&redrawn, 0, sizeof(redrawn));
  titlelen = (title_len_s){.screen = -1, .stat = -1, .chart = -1};
}

static inline void reset_actkey_flags(int key) {
  switch (key) {
    case  3 : // ^C
//  case  27: // Esc
    case 'q':
      at_quit = true;
      break;
    case '?':
    case 'h':
    case 'b': // bit pattern
    case 'c': // number of cycles
    case 'd': // display modes
#ifdef WITH_MPLS
    case 'e': // [ActionMPLS]
#endif
    case 'f': // first ttl
    case 'i': // interval
    case 'j': // [ActionJitter]
#ifdef WITH_IPINFO
    case 'l': // [ActionAS]
    case 'L': // [ActionII]
#endif
    case 'm': // max ttl
#ifdef ENABLE_DNS
    case 'n': // [ActionDNS]
#endif
    case 'o': // fields to display and their order
    case ' ':
    case 'p': // [ActionPauseResume]
#ifdef IP_TOS
    case 'Q': // qos
#endif
    case 's': // payload size
    case 't': // [ActionTCP]
    case 'u': // [ActionUDP]
    case 'x': // [ActionCache]
      require_redraw();
      break;
#ifdef WITH_IPINFO
    case 'y': // [ActionMultiII]
      if (IPINFOED)
        require_redraw();
      break;
#endif
    default: break;
  }
}

#ifdef WITH_MOUSE
#define CRD_ENCLOSE(crd) (                       \
  ((crd).x0 <= event.x) && (event.x <= (crd).x1) \
  &&                                             \
  ((crd).y0 <= event.y) && (event.y <= (crd).y1) \
)
#endif

key_action_t tui_keyaction(void) {
  WINDOW *win = area[NDX_LABEL].win; if (!win)  return ActionNone;
  int ch = wgetch(win); if (!ch || (ch == ERR)) return ActionNone;
#ifdef KEY_RESIZE
  // skip resize keys
  if (ch == KEY_RESIZE) { // cleanup by batch
    require_redraw();
    for (uint i = 0; (ch == KEY_RESIZE) && (i < GETCH_BATCH); i++)
      ch = wgetch(win);
    if (ch == KEY_RESIZE) // otherwise flush
      flushinp();
  }
#endif
#ifdef WITH_MOUSE
  // map mouse events to keys
  if (mouse_on && ch == KEY_MOUSE) {
    MEVENT event = {0};
    if (getmouse(&event) == OK
      // && (event.bstate & BUTTON1_CLICKED) /*already filtered*/
    ) {
      ch =
         CRD_ENCLOSE(crd_topbar.menu)  ? 'h' /*temporarily 'help', TODO: menu*/ :
         CRD_ENCLOSE(crd_topbar.quit)  ? 'q' :
         //
         CRD_ENCLOSE(crd_status.jttr)  ? 'j' :
         CRD_ENCLOSE(crd_status.chart) ? 'd' :
#ifdef ENABLE_DNS
         CRD_ENCLOSE(crd_status.dns)   ? 'n' :
#endif
#ifdef WITH_IPINFO
         CRD_ENCLOSE(crd_status.asn)   ? 'l' :
         CRD_ENCLOSE(crd_status.info)  ? 'L' :
#endif
#ifdef WITH_MPLS
         CRD_ENCLOSE(crd_status.mpls)  ? 'e' :
#endif
         0;
      LOGMSG("mouse event: x=%d, y=%d, key='%c'", event.x, event.y, ch);
    }
  }
#endif
  reset_actkey_flags(ch);
//
  key_action_t action = ActionNone /*0*/;
  if (ch < UINT8_MAX) { // 8bit char
    tui_key_fn fn = actfn_map[ch];
    if (fn) { // handle it here
      WINDOW *w = (fn == tui_key_h) ? stdscr : win;
      if (w)
        fn(w);
    } else    // or somewhere else
      action = action_map[ch];
  } else switch (ch) {  // more than 8 bits
    case KEY_UP:   // decrease by one line
      tui_key_plus(NULL);
      break;
    case KEY_DOWN: // increase by one line
      tui_key_minus(NULL);
      break;
    case KEY_PPAGE: // PageUp:   decrease by 'page'-lines
      LOGMSG("page down (%d lines)", LINES_PER_PAGE);
      linedown(LINES_PER_PAGE);
      break;
    case KEY_NPAGE: // PageDown: increase by 'page'-lines
      LOGMSG("page up (%d lines)", LINES_PER_PAGE);
      lineup(LINES_PER_PAGE);
      break;
    default: break;
  }
  return action;
}

#ifdef WITH_MPLS
static int printw_mpls(WINDOW *win, const mpls_data_t *m) NONNULL(1, 2);
static int printw_mpls(WINDOW *win, const mpls_data_t *m) {
  char buff[64] = {0};
  for (int i = 0; i < m->n; i++) {
    waddstr(win, mpls2str(&m->label[i], sizeof(buff), buff, INDENT_NUMB));
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
  if (IPINFOED) {
    char info[NAMELEN] = {0};
    ipinfo_data_fix(sizeof(info), info, at, ndx);
    if (info[0])
      waddstr(win, info);
  }
#endif
  bool down = !host[at].up;
  if (down)
    wattron(win, A_BOLD);
#ifdef ENABLE_DNS
  const char *name = dns_ptr_lookup(at, ndx);
  if (name) {
    waddstr(win, name);
    if (run_opts.both) {
      char str[MAX_ADDRSTRLEN] = {0};
      waddstr(win, " (");
      waddstr(win, addr2str(addr, sizeof(str), str));
      waddch(win, ')');
    }
  } else
#endif
  { char str[MAX_ADDRSTRLEN] = {0};
    waddstr(win, addr2str(addr, sizeof(str), str)); }
  if (down)
    wattroff(win, A_BOLD);
}

static void seal_n_bell(int at, int max) {
  const int bell_at = SAVED_PINGS - 3; // wait at least -i interval for reliability
  if (host[at].saved[bell_at] == CT_UNKN) {
    host[at].saved[bell_at] = CT_SEAL; // sealed
    if (run_opts.bell && (at != (max - 1)))
      return;
    if (run_opts.audible)
      beep();
    if (run_opts.visible)
      flash();
  }
}

static int print_stat(WINDOW *win, int at, int y, int x, int max) NONNULL(1);
static int print_stat(WINDOW *win, int at, int y, int x, int max) { // statistics
  if (wmove(win, y, x) == ERR) return ERR;
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (!stat)
      break;
    const char *str = net_settled_elem(at, stat->key);
    wprintw(win, "%*s", stat->min, str ? str : "");
  }
  if (run_opts.audible || run_opts.visible)
    seal_n_bell(at, max);
  return wmove(win, y + 1, 0);
}

static void print_addr_extra(WINDOW *win, int at) NONNULL(1);
static void print_addr_extra(WINDOW *win, int at) { // multipath + mpls
  for (int ndx = 0; ndx < MAXPATH; ndx++) { // multipath
    if (ndx != host[at].current) { // not printed yet
      if (!addr_exist(&IP_AT_NDX(at, ndx)))
        break;
      wprintw(win, "%*s", INDENT_NUMB, "");
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
}

static void print_hops(WINDOW *win, int statx) NONNULL(1);
static void print_hops(WINDOW *win, int statx) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    int y = getcury(win);
    if (wmove(win, y, 0) == ERR)
      break;
    wprintw(win, AT_FMT, at + 1);
    waddch(win, ' ');
    if (addr_exist(&CURRENT_IP(at))) {
      printw_addr(win, at, host[at].current);
      if (print_stat(win, at, y, statx, max) == ERR)
        break;
#ifdef WITH_MPLS
      if (run_opts.mpls)
        printw_mpls(win, &CURRENT_MPLS(at));
#endif
      print_addr_extra(win, at);
    } else {
      waddstr(win, UNKN_ITEM);
      if (wmove(win, y + 1, 0) == ERR)
        break;
      if ((at < (max - 1)) && (print_stat(win, at, y, statx, max) == ERR))
        break;
    }
  }
  wmove(win, 0, 0);
}

static bool histoaddr(WINDOW *win, int at) NONNULL(1);
static bool histoaddr(WINDOW *win, int at) {
  t_ipaddr *addr = &CURRENT_IP(at);
  bool exist = addr_exist(addr);
  if (exist) {
    if (!host[at].up)
      wattron(win, A_BOLD);
#ifdef WITH_IPINFO
    if (IPINFOED) {
      char info[NAMELEN] = {0};
      ipinfo_data_fix(sizeof(info), info, at, host[at].current);
      if (info[0])
        waddstr(win, info);
    }
#endif
#ifdef ENABLE_DNS
    const char *name = dns_ptr_lookup(at, host[at].current);
    if (name)
      waddstr(win, name);
    else {
      char str[MAX_ADDRSTRLEN] = {0};
      waddstr(win, addr2str(addr, sizeof(str), str));
    }
#else
    { char str[MAX_ADDRSTRLEN] = {0};
      waddstr(win, addr2str(addr, sizeof(str), str)); }
#endif
    if (!host[at].up)
      wattroff(win, A_BOLD);
  } else
    waddstr(win, UNKN_ITEM);
  return exist;
}

static void histochar(WINDOW *win, int at, int indent) NONNULL(1);
static void histochar(WINDOW *win, int at, int indent) {
  int width = getmaxx(win) - indent;
  if (width > 0) {
    if (width > SAVED_PINGS)
      width = SAVED_PINGS;
    chart_area(win, width, &host[at].saved[SAVED_PINGS - width]);
  }
}

static void histogram(WINDOW *win, int indent) NONNULL(1);
static void histogram(WINDOW *win, int indent) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    int y = getcury(win);
    if (wmove(win, y, 0) == ERR)
      break;
    wprintw(win, AT_FMT, at + 1);
    waddch(win, ' ');
    if (histoaddr(win, at) &&
        (wmove(win, y, indent - 2/*lpad(1) + rpad(1)*/) == OK))
    {
      waddch(win, ' ');
      histochar(win, at, indent);
      if (run_opts.audible || run_opts.visible)
        seal_n_bell(at, max);
    }
    if (wmove(win, y + 1, 0) == ERR)
      break;
  }
}

static int get_stat_title_len(void) {
  int len = 0;
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (stat)
      len += (stat->min > stat->len) ? stat->min : stat->len + 1;
  }
  return (len < 0) ? 0 : len;
}

static inline int tui_fit_posx(int pos, int len, int maxx) {
  int lcols = maxx - 1 - len;
  return (pos < lcols) ? pos : lcols;
}

static void display_main_labels(WINDOW *win, int indent) NONNULL(1);
static void display_main_labels(WINDOW *win, int indent) {
  if (wmove(win, 1, indent) == ERR)
    return;
  bool custom = is_custom_fld();
  int maxx = getmaxx(win);
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (!stat)
      break;
#define SUP1_NDX 0 // "Packets" or "Custom fields"
#define SUP2_NDX 3 // "Pings"
    if ((i == SUP1_NDX) || (i == SUP2_NDX)) {
      // add suptitles
      int curx = getcurx(win);
      int dx   = (stat->min > stat->len) ? (stat->min - stat->len) : 1;
      int pos  = curx + dx;
      if ((i == SUP1_NDX) && custom) {
        // "Custom fields"
        const char div[] = ": ";
        int div_len = sizeof(div) - 1;
        int ufl = (maxx > div_len) ? ustrnlen(USR_FIELDS_STR, maxx - div_len) : 0;
        int len = ufl + div_len + strnlen(fld_active, MAXFLD);
        mvwaddstr(win, 0, tui_fit_posx(pos, len, maxx), USR_FIELDS_STR);
        waddstr(win, div);
        waddstr(win, fld_active);
      } else if (!custom) {
        // "Packets" or "Pings"
        const char *sub = (i == SUP1_NDX) ? PINGS_STR : PACKETS_STR;
        int len = ustrnlen(sub, maxx);
        mvwaddstr(win, 0, tui_fit_posx(pos, len, maxx),  i ? PINGS_STR : PACKETS_STR);
      }
      wmove(win, 1, curx);
    }
    wprintw(win, "%*s", (stat->min > stat->len) ? (stat->min - stat->len) : 1, "");
    if (stat->name)
      waddstr(win, stat->name);
  }
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

static int tui_print_args(char buf[], size_t size) NONNULL(1);
static int tui_print_args(char buf[], size_t size) {
  int len = snprinte(buf, size, " (");
  if (len < 0)
    return len;
  int iasp = len;
  BOOL_OPT2STR(udp,     PAR_UDP_STR);
  BOOL_OPT2STR(tcp,     PAR_TCP_STR);
#ifdef WITH_MPLS
  BOOL_OPT2STR(mpls,    PAR_MPLS_STR);
#endif
#ifdef WITH_IPINFO
  BOOL_OPT2STR(asn,     PAR_ASN_STR);
  BOOL_OPT2STR(ipinfo,  PAR_II_STR);
  if (IPINFOED)
    BOOL_OPT2STR(multi, PAR_MII_STR);
#endif
#ifdef ENABLE_DNS
  BOOL_OPT2STR(dns,     PAR_DNS_STR);
#endif
  BOOL_OPT2STR(jitter,  PAR_JITTER_STR);
  //
  INT_OPT2STR(chart,    PAR_CHART_STR, "%u");
  BOOL_OPT2STR(color,   PAR_COLOR_STR);
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
  if (STR_EQ(buf, EMPTY_ARGS, sizeof(EMPTY_ARGS)))
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

static void redraw_chart_title(WINDOW *win, int indent) NONNULL(1);
static void redraw_chart_title(WINDOW *win, int indent) {
  werase(win);
  static char chart_title[256]; // long enough?
  if (titlelen.chart < 0) {
    memset(chart_title, 0, sizeof(chart_title));
    int width = getmaxx(win) - indent;
    int len = snprinte(chart_title, sizeof(chart_title), "%s: %d %s",
      HISTOGRAM_STR,
      (width > SAVED_PINGS) ? SAVED_PINGS : width,
      HCOLS_STR);
    if (len >= 0)
      titlelen.chart = ustrnlen(chart_title, getmaxx(win));
  }
  if (titlelen.chart > 0) {
    int x = (getmaxx(win) - titlelen.chart) / 2;
    mvwaddstr(win, 0, (x > 0) ? x : 0, chart_title);
  }
  wrefresh(win);
}

static void redraw_charts(WINDOW *label, WINDOW *work) NONNULL(1, 2);
static void redraw_charts(WINDOW *label, WINDOW *work) {
  int indent = HOSTINFOMAX;
#ifdef WITH_IPINFO
  if (IPINFOED)
    indent += ipinfo_width();
#endif
  if (!redrawn.chart_title) {
    redraw_chart_title(label, indent);
    redrawn.chart_title = true;
  }
  //
  werase(work);
  chart_scale(display_offset);
  histogram(work, indent);
  if (wmove(work, getcury(work) + 1, 0) != ERR)
    print_scale(work);
  wrefresh(work);
}

static int redraw_labels(WINDOW *win, int indent) NONNULL(1);
static int redraw_labels(WINDOW *win, int indent) {
  werase(win);
  wattron(win, A_BOLD);
#ifdef WITH_IPINFO
  if (IPINFOED) {
    char info[NAMELEN] = {0};
    ipinfo_head_fix(sizeof(info), info);
    if (info[0])
      mvwaddstr(win, 1, indent, info);
    indent += ipinfo_width(); // indent: "NN. " + IPINFO
  }
#endif
  mvwaddstr(win, 1, indent, HOST_STR);
  if (titlelen.stat < 0)
    titlelen.stat = get_stat_title_len();
  indent = getmaxx(win) - (titlelen.stat + 1);
  if (indent < 0)
    indent = 0;
  display_main_labels(win, indent);
  wattroff(win, A_BOLD);
  wrefresh(win);
  return indent;
}

// menu-n-status: print items and keep coordinates for mouse hadlers
//
static void print_menuitem(WINDOW *win, char ch, const char *name) NONNULL(1, 3);
static void print_menuitem(WINDOW *win, char ch, const char *name) {
  waddch(win, ' ');
  waddch(win, ch | A_BOLD);
  waddstr(win, name);
}
//
static inline const char* onoff_str(bool on) {return on ? ONN_STR : OFF_STR;}
//
static void print_statusitem(WINDOW *win, const char *name, const char *value, const bool *onoff) NONNULL(1, 2);
static void print_statusitem(WINDOW *win, const char *name, const char *value, const bool *onoff) {
  waddch(win, ' ');
  waddstr(win, name);
  waddch(win, '=');
  const char *valstr = onoff ? onoff_str(*onoff) : ((value && value[0]) ? value : NULL);
  waddstr(win, valstr ? valstr : onoff_str(false));
}
//
#ifdef WITH_MOUSE
static void print_menukeep(WINDOW *win, const char *name,
  int dx, int dy, crd_s *crd, int x, int y) NONNULL(1, 2, 5);
static void print_menukeep(WINDOW *win, const char *name, int dx, int dy, crd_s *crd, int x, int y) {
  mvwaddstr(win, y, x, name);
  crd->x0 = dx + x;
  crd->y0 = dy + y;
  crd->x1 = dx + getcurx(win);
  crd->y1 = dy + getcury(win);
  if (getcurx(win) < (getmaxx(win) - 1))
    crd->x1--; /// uccessful addstr()
  LOGMSG("menu(%s): x0=%d y0=%d x1=%d y1=%d (w=%d h=%d)",
    name, crd->x0, crd->y0, crd->x1, crd->y1,
    crd->x1 - crd->x0 + 1, crd->y1 - crd->y0 + 1);
}
//
static void print_statuskeep(WINDOW *win, const char *name, const char *value,
  const bool *onoff, int dx, int dy, crd_s *crd) NONNULL(1, 2, 7);
static void print_statuskeep(WINDOW *win, const char *name, const char *value,
  const bool *onoff, int dx, int dy, crd_s *crd)
{
  waddch(win, ' ');
  crd->x0 = dx + getcurx(win);
  crd->y0 = dy + getcury(win);
  waddstr(win, name);
  waddch(win, '=');
  const char *valstr = onoff ? onoff_str(*onoff) : ((value && value[0]) ? value : NULL);
  waddstr(win, valstr ? valstr : onoff_str(false));
  crd->x1 = dx + getcurx(win);
  crd->y1 = dy + getcury(win);
  if (getcurx(win) < (getmaxx(win) - 1))
    crd->x1--; // successful addstr()
  LOGMSG("status(%s): x0=%d y0=%d x1=%d y1=%d (w=%d h=%d)",
    name, crd->x0, crd->y0, crd->x1, crd->y1,
    crd->x1 - crd->x0 + 1, crd->y1 - crd->y0 + 1);
}
#endif
//

static void redraw_top(WINDOW *win) NONNULL(1);
static void redraw_top(WINDOW *win) {
  static char title_cache[LINEMAXLEN];
  werase(win);
  //
  if (titlelen.screen < 0) { // generate title and cache it
    char buff[LINEMAXLEN] = {0};
    const char *pretitle = screen_title;
    if (opt_sum.un) {
      int len = snprinte(buff, sizeof(buff), "%s", screen_title);
      if (len >= 0) {
        pretitle = buff;
        int inc = tui_print_args(buff + len, sizeof(buff) - len);
        if (inc < 0)
          pretitle = screen_title; // else len += inc;
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
    mvwaddstr(win, 0, (x > 0) ? x : 0, title);
  }
#ifdef WITH_MOUSE
  if (mouse_enabled && (tuilook != OLDLOOK)) {
    int dx = getbegx(win), dy = getbegy(win);
    print_menukeep(win, menu_icon, dx, dy, &crd_topbar.menu, 0, 0);
    print_menukeep(win, quit_icon, dx, dy, &crd_topbar.quit,
      getmaxx(win) - (quit_icon_len ? quit_icon_len : 3), 0);
  }
#endif
  wrefresh(win);
}

#ifdef WITH_MOUSE
static inline void status_n_keep_crd(WINDOW *win, uint len, char buff[len]) NONNULL(1, 3);
static inline void status_n_keep_crd(WINDOW *win, uint len, char buff[len]) {
  int dx = getbegx(win), dy = getbegy(win);
  print_statuskeep(win, JTTR_STR, NULL, &run_opts.jitter, dx, dy, &crd_status.jttr);
  buff[0] = 0;
  if (run_opts.chart)
    snprinte(buff, len, "%d", run_opts.chart | (run_opts.color ? (1 << 3) : 0));
  print_statuskeep(win, CHART_STR, buff, NULL, dx, dy, &crd_status.chart);
#ifdef ENABLE_DNS
  print_statuskeep(win, DNS_STR, NULL, &run_opts.dns, dx, dy, &crd_status.dns);
#endif
#ifdef WITH_IPINFO
  print_statuskeep(win, ASN_STR, NULL, &run_opts.asn, dx, dy, &crd_status.asn);
  buff[0] = 0;
  if (run_opts.ipinfo)
    ipinfo_head_div(len, buff, COMMA, 0);
  print_statuskeep(win, INFO_STR, buff, NULL, dx, dy, &crd_status.info);
#endif
#ifdef WITH_MPLS
  print_statuskeep(win, MPLS_STR, NULL, &run_opts.mpls, dx, dy, &crd_status.mpls);
#endif
}
#endif

static inline void status_no_crd(WINDOW *win, uint len, char buff[len]) NONNULL(1, 3);
static inline void status_no_crd(WINDOW *win, uint len, char buff[len]) {
#ifdef ENABLE_DNS
  print_statusitem(win, DNS_STR,  NULL, &run_opts.dns);
#endif
#ifdef WITH_IPINFO
  print_statusitem(win, ASN_STR,  NULL, &run_opts.asn);
  buff[0] = 0;
  if (run_opts.ipinfo)
    ipinfo_head_div(len, buff, COMMA, 0);
  print_statusitem(win, INFO_STR, buff, NULL);
#endif
#ifdef WITH_MPLS
  print_statusitem(win, MPLS_STR, NULL, &run_opts.mpls);
#endif
}

static void redraw_status(WINDOW *win) NONNULL(1);
static void redraw_status(WINDOW *win) {
  char buff[LINEMAXLEN] = {0};
  if (!redrawn.field_status) {
    werase(win);
    redrawn.field_status = true;
    // add menu hints
    if (tuilook == OLDLOOK) {
      mvwaddstr(win, 0, 0, MENU_STR);
      waddch(win, ':');
      print_menuitem(win, 'h', _HINTS_STR);
      print_menuitem(win, 'q', _QUIT_STR);
    } else {
#ifdef WITH_MOUSE
      if (mouse_enabled && (tuilook != OLDLOOK))
        status_n_keep_crd(win, sizeof(buff), buff);
      else
#endif
      { status_no_crd(win, sizeof(buff), buff); }
    }
  }
  //
  buff[0] = 0;
  int len = 0;
  // add source host
  if (tuilook == OLDLOOK) {
    len = snprinte(buff, sizeof(buff), "%.*s", (int)strnlen(srchost, getmaxx(win) / 2), srchost);
    if (len < 0)
      len = 0;
  }
  // add datetime
  char str[64] = {0};
  const char *date = tui_datetime ? tui_datetime(time(NULL), sizeof(str), str) : NULL;
  if (date && date[0])
    len += snprinte(buff + len, sizeof(buff) - len, len ? ": %s" : "%s", date);
  static int dt_last_xpos;
  // print it rigth aligned
  if ((len > 0) && buff[0]) {
    dt_last_xpos = getmaxx(win) - ustrnlen(buff, sizeof(buff)) - 1;
    mvwaddstr(win, 0, dt_last_xpos, buff);
  }
  else if ((dt_last_xpos > 0) && (wmove(win, 0, dt_last_xpos) == OK))
    wclrtoeol(win);
  //
  wrefresh(win);
}

static inline void redraw_mainarea(WINDOW *label, WINDOW *work) NONNULL(1, 2);
static inline void redraw_mainarea(WINDOW *label, WINDOW *work) {
  if (chart_mode)
    redraw_charts(label, work);
  else {
    static int stat_indent;
#ifdef WITH_IPINFO
    if (ipinfo_rewidth) {
      ipinfo_rewidth = false;
      stat_indent = 0; // indicate to redraw labels
    }
#endif
    if (!(stat_indent && redrawn.labels)) {
      stat_indent = redraw_labels(label, INDENT_NUMB);
      if (!redrawn.labels)
        redrawn.labels = true;
    }
    werase(work);
    print_hops(work, stat_indent);
    wrefresh(work);
  }
}

static void create_area(uint ndx) {
  static int y;
  if (ndx < ARRAY_LEN(area)) {
    int h = area[ndx].height;
    if (h < 0)
      h += LINES;
    WINDOW *win = newwin(h, 0/*max*/, y, 0);
    if (win) {
      wrefresh(win);
      keypad(win, TRUE);
      area[ndx].win = win;
      y += h;
      LOGMSG("#%u: x0=%d y0=%d x1=%d y1=%d (width=%d height=%d)", ndx,
        getbegx(win), getbegy(win), getmaxx(win), getmaxy(win),
        getmaxx(win) - getbegx(win), getmaxy(win) - getbegy(win));
    }
  } else {
    y = 0; // indicate y-reset with out-of-range index
    LOGMSG("%s", "area y-reset");
  }
}

static void free_areas(void) {
  for (uint i = 0; i < ARRAY_LEN(area); i++)
    if (area[i].win) {
      delwin(area[i].win);
      area[i].win = NULL;
      LOGMSG("#%u: done", i);
    }
}

static inline bool areas_okay(void) {
  for (uint i = 0; i < ARRAY_LEN(area); i++)
    if (!area[i].win)
      return false;
 return true;
}

static bool areas_ready(void) {
  static int my_cols, my_lines;
  bool okay = areas_okay() && (my_cols == COLS) && (my_lines == LINES);
  if (!okay) {
    my_cols  = COLS;
    my_lines = LINES;
    require_redraw();
    // create areas
    free_areas();
    create_area(ARRAY_LEN(area)); // reset `y' position
    int *order = (tuilook == OLDLOOK) ? area_old_order : area_new_order;
    for (uint i = 0; i < ARRAY_LEN(area); i++)
      create_area(order[i]);
    okay = areas_okay();
  }
  return okay;
}

static void areas_bg(short bg) {
  wbkgd(area[NDX_TOP   ].win, COLOR_PAIR(bg));
  wbkgd(area[NDX_STATUS].win, COLOR_PAIR(bg));
}

static inline void redraw_areas(void) {
  if (!redrawn.top) {
    redraw_top(area[NDX_TOP].win);
    redrawn.top = true;
  }
  redraw_mainarea(area[NDX_LABEL].win, area[NDX_WORK].win);
  redraw_status(area[NDX_STATUS].win);
}

void tui_redraw(void) {
  if (areas_ready())
    redraw_areas();
  else {
    erase();
    printw("TUI init areas: failed");
    refresh();
  }
}

bool tui_open(void) {
  tui_datetime = (tuilook == NEWLOOK) ? datetime_FT : datetime_c;
#ifdef LOGMOD
  { char str[64] = {0};
    const char *date = tui_datetime(time(NULL), sizeof(str), str);
    LOGMSG("%s", date); }
#endif
  screen_ready = initscr();
  LOGMSG("screen ready: %d", screen_ready);
  if (!screen_ready) {
    warnx("TUI initscr() failed");
    return false;
  }
#ifdef WITH_MOUSE
  LOGMSG("mouse: %s", mouse_enabled ? "enabled" : "disabled");
  mouse_on = mouse_enabled;
  if (mouse_enabled) {
    menu_icon = utf_compat ? MENU_ICON_UTF8 : MENU_ICON_ASCII;
    quit_icon = utf_compat ? QUIT_ICON_UTF8 : QUIT_ICON_ASCII;
//    menu_icon_len = ustrnlen(menu_icon, NAMELEN);
    quit_icon_len = ustrnlen(quit_icon, NAMELEN);
    mousemask(BUTTON1_CLICKED | REPORT_MOUSE_POSITION, NULL);
    LOGMSG("unicode compat: %s", utf_compat ? "true" : "false");
  }
#endif
  //
  raw();
  noecho();
  keypad(stdscr, TRUE);
  short bg_pair = (start_color() == OK) ? color_charts() : -1;
  prepare_charts();
  bool okay = areas_ready();
  if (okay && (bg_pair >= 0))
    areas_bg(bg_pair);
  // init title
  titlelen = (title_len_s){.screen = -1, .stat = -1, .chart = -1};
  if (mtr_args[0])
    snprinte(screen_title, sizeof(screen_title), "%s %s %s", PACKAGE_NAME, mtr_args, dsthost);
  else
    snprinte(screen_title, sizeof(screen_title), "%s %s", PACKAGE_NAME, dsthost);
  screen_title_len = screen_title[0] ? ustrnlen(screen_title, getmaxx(area[NDX_TOP].win)) : 0;
  //
  curs_set(0);
  return okay;
}

void tui_confirm(void) {
  WINDOW *win = area[NDX_WORK].win;
  LOGMSG("at_quit=%d screen_ready=%d area=%p", at_quit, screen_ready, (void*)win);
  if (at_quit || !win || !screen_ready)
    return;
  at_quit = true;
  int y = getmaxy(win) - 2;
  wmove(win, y++, 0); wclrtoeol(win);
  wmove(win, y--, 0); wclrtoeol(win);
  const char dot3[] = " ...";
  int dot3len = sizeof(dot3) - 1, maxx = getmaxx(win);
  int len = (maxx > dot3len) ? ustrnlen(ANYQUIT_STR, maxx - dot3len) + dot3len : maxx;
  mvwaddstr(win, y, (maxx - len) / 2, ANYQUIT_STR);
  waddstr(win, dot3);
  flushinp();
  wgetch(win);
}

void tui_close(void) {
#ifdef LOGMOD
  { char str[64] = {0};
    const char *date = tui_datetime ? tui_datetime(time(NULL), sizeof(str), str) : NULL;
    LOGMSG("%s", date ? date : datetime_c(time(NULL), sizeof(str), str)); }
#endif
  MOUSE_OFF;
  if (stdscr && screen_ready) {
    endwin();
    screen_ready = false;
  }
  free_areas();
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

