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

//#include <stdio.h>
#include <string.h>

#if defined(LOG_TUI) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_TUI) && defined(LOGMOD)
#undef LOGMOD
#endif

#include "action.h"
#include "chart.h"
#include "ipinfo.h"
#include "net.h"
#include "nls.h"
#include "aux.h"

typedef void (*tui_key_fn)(WINDOW *win) NONNULL(1);

enum {
  LINES_PER_PAGE =   5,
  INDENT_HINT    =  12,
  GETCH_BATCH    = 100,
};

#ifdef WITH_MOUSE
//
#define CRD_ENCLOSE(crd) (                       \
  ((crd).x0 <= event.x) && (event.x <= (crd).x1) \
  &&                                             \
  ((crd).y0 <= event.y) && (event.y <= (crd).y1) \
)
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
  crd_s proto;
} crd_status_s;
static crd_status_s crd_status;
//
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
#define MOUSE_ON  do { if (run_opts.mouse) mouse_on = true;  } while (0)
#define MOUSE_OFF do { if (run_opts.mouse) mouse_on = false; } while (0)
//
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

uint display_offset;

//

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
    {.key = "P", .hint = CMD_P_STR},
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

static void tui_key_o_hints(int x0, int y0) {
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
  ['P'] = ActionProto,
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

static void reset_by_key(int key, void (*reset)(void)) NONNULL(2);
static void reset_by_key(int key, void (*reset)(void)) {
  switch (key) {
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
    case 'P': // [ActionProto]
#ifdef IP_TOS
    case 'Q': // qos
#endif
    case 's': // payload size
    case 't': // [ActionTCP]
    case 'u': // [ActionUDP]
    case 'x': // [ActionCache]
      reset();
      break;
#ifdef WITH_IPINFO
    case 'y': // [ActionMultiII]
      if (IPINFOED)
        reset();
      break;
#endif
  }
}

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

#ifdef WITH_MOUSE
static int mouse2key(void) {
  MEVENT event = {0};
  int ch = 0;
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
       CRD_ENCLOSE(crd_status.proto) ? 'P' :
       0;
    LOGMSG("mouse event: x=%d, y=%d, key='%c'", event.x, event.y, ch);
  }
  return ch;
}
#endif

// global

key_action_t tui_actionw(WINDOW *win, void (*reset)(void)) { // NONNULL(1)
  key_action_t action = ActionNone /*0*/;
  int ch = wgetch(win);
  if (!ch || (ch == ERR))
    return action;
#ifdef KEY_RESIZE
  // skip resize keys
  if (ch == KEY_RESIZE) { // cleanup by batch
    if (reset)
      reset();
    for (uint i = 0; (ch == KEY_RESIZE) && (i < GETCH_BATCH); i++)
      ch = wgetch(win);
    if ((ch == KEY_RESIZE) || (ch == ERR)) { // otherwise flush
      flushinp();
      return action;
    }
  }
#endif
#ifdef WITH_MOUSE
  // map mouse events to keys
  if (mouse_on && (ch == KEY_MOUSE)) {
    ch = mouse2key();
    if (!ch)
      return action;
  }
#endif
  if (reset)
    reset_by_key(ch, reset);
//
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
  }
  return action;
}

#ifdef WITH_MOUSE
void topbar_icons(WINDOW *win) { // NONNULL(1)
  if (run_opts.mouse) {
    int dx = getbegx(win), dy = getbegy(win);
    print_menukeep(win, menu_icon, dx, dy, &crd_topbar.menu, 0, 0);
    print_menukeep(win, quit_icon, dx, dy, &crd_topbar.quit,
      getmaxx(win) - (quit_icon_len ? quit_icon_len : 3), 0);
  }
}
#endif

#ifdef WITH_MOUSE
void status_n_keep_crd(WINDOW *win, uint len, char buff[len]) NONNULL(1, 3);
void status_n_keep_crd(WINDOW *win, uint len, char buff[len]) {
  int dx = getbegx(win), dy = getbegy(win);
  print_statuskeep(win, JTTR_STR, NULL, &run_opts.jitter, dx, dy, &crd_status.jttr);
  buff[0] = 0;
  if (run_opts.chart)
    snprinte(buff, len, "%d", CHART_MODE);
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
  buff[0] = 0;
  snprinte(buff, len, "%s", USED_PROTO);
  print_statuskeep(win, PROTO_STR, buff, NULL, dx, dy, &crd_status.proto);
}
#endif

void status_no_crd(WINDOW *win, uint len, char buff[len]) NONNULL(1, 3);
void status_no_crd(WINDOW *win, uint len, char buff[len]) {
  print_statusitem(win, JTTR_STR, NULL, &run_opts.jitter);
  buff[0] = 0;
  if (run_opts.chart)
    snprinte(buff, len, "%d", CHART_MODE);
  print_statusitem(win, CHART_STR, buff, NULL);
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
  buff[0] = 0;
  snprinte(buff, len, "%s", USED_PROTO);
  print_statusitem(win, PROTO_STR, buff, NULL);
}

#ifdef WITH_MOUSE
void enable_mouse(void) {
  mouse_on = run_opts.mouse;
  if (run_opts.mouse) {
    menu_icon = utf_compat ? MENU_ICON_UTF8 : MENU_ICON_ASCII;
    quit_icon = utf_compat ? QUIT_ICON_UTF8 : QUIT_ICON_ASCII;
//    menu_icon_len = ustrnlen(menu_icon, NAMELEN);
    quit_icon_len = ustrnlen(quit_icon, NAMELEN);
    mousemask(BUTTON1_CLICKED | REPORT_MOUSE_POSITION, NULL);
  }
  LOGMSG("mouse: %s", run_opts.mouse ? "enabled" : "disabled");
}
//
void disable_mouse(void) {
  MOUSE_OFF;
  if (run_opts.mouse)
    mousemask(0, NULL);
  LOGMSG("mouse: %s", run_opts.mouse ? "enabled" : "disabled");
}
#endif

