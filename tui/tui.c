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
#include "action.h"
#ifdef WITH_MENUPAN
#include "menupan.h"
#endif
#include "nls.h"
#include "aux.h"
#include "net.h"

#ifdef ENABLE_DNS
#include "dns.h"
#endif

#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#define VUSLASH "│"

enum {
  HOSTINFOMAX =   30,
  GETCH_BATCH =  100,
  LINEMAXLEN  = 1024,
};

enum {NDX_TOP = 0, NDX_STATUS, NDX_LABEL, NDX_WORK};
typedef struct {
  WINDOW *win;
#ifdef WITH_MENUPAN
  PANEL *pan;
#endif
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
static bool quit_acked, screen_ready;

typedef struct {
  int screen, stat, chart;
} title_len_s;
static title_len_s titlelen;

static void require_redraw(void) {
  memset(&redrawn, 0, sizeof(redrawn));
  titlelen = (title_len_s){.screen = -1, .stat = -1, .chart = -1};
  LOGMSG("%s", "flags are reset");
}

key_action_t tui_keyaction(void) {
  WINDOW *win = area[NDX_LABEL].win;
  key_action_t action = win ? tui_actionw(win, require_redraw) : ActionNone;
  if (action == ActionQuit)
    quit_acked = true;
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

#define ARGSPACE (len ? " " : "")
//
#define ADD_FMT_ARG(fmt, ...) do {   \
  int max = size - len;              \
  if (max <= 0) return size;         \
  int inc = snprinte(buf + len, max, \
    fmt, __VA_ARGS__);               \
  if (inc < 0) return len;           \
  if (inc > 0) len += inc;           \
} while (0)
//
#define BOOL_OPT2STR(tag, msg) do {   \
  if (run_opts.tag != ini_opts.tag)   \
    ADD_FMT_ARG("%s%c%s", ARGSPACE,   \
      run_opts.tag ? '+' : '-', msg); \
} while (0)
//
#define INT_OPT2STR(tag, prfx, fmt) do { \
  if (run_opts.tag != ini_opts.tag)      \
    ADD_FMT_ARG("%s%s" fmt, ARGSPACE,    \
      prfx, run_opts.tag);               \
} while (0)
//
static int tui_print_args(uint size, char buf[size]) NONNULL(2);
static int tui_print_args(uint size, char buf[size]) {
  int len = 0;
  if (tuilook == OLDLOOK) {
#ifdef ENABLE_DNS
    BOOL_OPT2STR(dns,    PAR_DNS_STR);
#endif
    BOOL_OPT2STR(jttr,   PAR_JITTER_STR);
    INT_OPT2STR(chart,   PAR_CHART_STR, "%u");
    BOOL_OPT2STR(color,  PAR_COLOR_STR);
#ifdef WITH_IPINFO
    BOOL_OPT2STR(asn,    PAR_ASN_STR);
    BOOL_OPT2STR(ipinfo, PAR_II_STR);
#endif
  }
#ifdef WITH_IPINFO
  if (IPINFOED)
    BOOL_OPT2STR(multi,  PAR_MII_STR);
#endif
  if (tuilook == OLDLOOK) {
#ifdef WITH_MPLS
    BOOL_OPT2STR(mpls,   PAR_MPLS_STR);
#endif
    BOOL_OPT2STR(udp,    PAR_UDP_STR);
    BOOL_OPT2STR(tcp,    PAR_TCP_STR);
  }
  //
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
  WREFRESH(win);
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
  WREFRESH(work);
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
  WREFRESH(win);
  return indent;
}

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
      char argstr[LINEMAXLEN / 2] = {0};
      if ((tui_print_args(sizeof(argstr), argstr) > 0) &&
          (snprinte(buff, sizeof(buff), "%s (%s)", screen_title, argstr) > 0))
        pretitle = buff;
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
  if (tuilook != OLDLOOK)
    topbar_icons(win);
#endif
  WREFRESH(win);
}

static void print_hintmenu(WINDOW *win, char ch, const char *name) NONNULL(1, 3);
static void print_hintmenu(WINDOW *win, char ch, const char *name) {
  waddch(win, ' ');
  waddch(win, ch | A_BOLD);
  waddstr(win, name);
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
      print_hintmenu(win, 'h', _HINTS_STR);
      print_hintmenu(win, 'q', _QUIT_STR);
    } else {
#ifdef WITH_MOUSE
      if (run_opts.mouse && (tuilook != OLDLOOK))
        status_n_keep_crd(win, sizeof(buff), buff);
      else
#endif
      { status_no_crd(win, sizeof(buff), buff); }
    }
  }
  //
  buff[0] = 0;
  // add datetime
  char str[64] = {0};
  const char *date = tui_datetime ? tui_datetime(time(NULL), sizeof(str), str) : NULL;
  int len = (date && date[0]) ? ((tuilook == OLDLOOK) ?
    snprinte(buff, sizeof(buff), "%.*s: %s",
      (int)strnlen(srchost, getmaxx(win) / 2), srchost, date) :
#ifdef WITH_UNICODE
    (utf_compat ?
      snprinte(buff, sizeof(buff), " %s %s", VUSLASH, date) :
#endif
      snprinte(buff, sizeof(buff), " %c %s", VSLASH, date))) : 0;
  static int dt_last_xpos;
  // print it rigth aligned
  if ((len > 0) && buff[0]) {
    dt_last_xpos = getmaxx(win) - ustrnlen(buff, sizeof(buff)) - 1;
    mvwaddstr(win, 0, dt_last_xpos, buff);
  }
  else if ((dt_last_xpos > 0) && (wmove(win, 0, dt_last_xpos) == OK))
    wclrtoeol(win);
  //
  WREFRESH(win);
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
    WREFRESH(work);
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
#ifdef WITH_MENUPAN
      area[ndx].pan = new_panel(win);
      if (!area[ndx].pan)
        LOGMSG("new_panel(#%u): %s", ndx, "failed");
#endif
      y += h;
      LOGMSG("#%u: x0=%d y0=%d x1=%d y1=%d (width=%d height=%d)", ndx,
        getbegx(win), getbegy(win), getmaxx(win), getmaxy(win),
        getmaxx(win) - getbegx(win), getmaxy(win) - getbegy(win));
    } else
      LOGMSG("newwin(#%u): %s", ndx, "failed");
  } else {
    y = 0; // indicate y-reset with out-of-range index
    LOGMSG("%s", "area y-reset");
  }
}

static void free_areas(void) {
  for (uint i = 0; i < ARRAY_LEN(area); i++) {
#ifdef WITH_MENUPAN
    if (area[i].pan) {
      del_panel(area[i].pan);
      area[i].pan = NULL;
    }
#endif
    if (area[i].win) {
      delwin(area[i].win);
      area[i].win = NULL;
      LOGMSG("#%u: done", i);
    }
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
#ifdef WITH_MENUPAN
  menu_bg = bg; // postponed wbkgd() set at first menu_handler() call
#endif
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
  if (areas_ready()) {
    redraw_areas();
    doupdate();
  } else {
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
  enable_mouse();
#endif
  LOGMSG("unicode compat: %s", utf_compat ? "true" : "false");
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
  LOGMSG("ack=%d ready=%d area=%p", quit_acked, screen_ready, (void*)win);
  if (!quit_acked && win && screen_ready) {
    quit_acked = true;
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
}

void tui_close(void) {
#ifdef LOGMOD
  { char str[64] = {0};
    const char *date = tui_datetime ? tui_datetime(time(NULL), sizeof(str), str) : NULL;
    LOGMSG("%s", date ? date : datetime_c(time(NULL), sizeof(str), str)); }
#endif
#ifdef WITH_MOUSE
  disable_mouse();
#endif
#ifdef WITH_MENUPAN
  free_menupan();
#endif
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

