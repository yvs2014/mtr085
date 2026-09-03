// part of mtr085: chart diagrams

#if defined(LOG_TUI) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_TUI) && defined(LOGMOD)
#undef LOGMOD
#endif

#ifdef WITH_UNICODE
#  ifndef _XOPEN_SOURCE_EXTENDED
#    define _XOPEN_SOURCE_EXTENDED
#  endif
//#  ifdef HAVE_WCHAR_H
//#    include <wchar.h>
//#  endif
#  ifdef __NetBSD__
#    define CCHAR_attr attributes
#    define CCHAR_chars vals
//#  elif defined(OPENSOLARIS_CURSES)
//#    define CCHAR_attr _at
//#    define CCHAR_chars _wc
#  else
#    define CCHAR_attr attr
#    define CCHAR_chars chars
#  endif
#endif // WITH_UNICODE

#include "chart.h"
#include "nls.h"
#include "net.h"
#include "aux.h"

typedef union {
  chtype  a; // ascii
#ifdef WITH_UNICODE
  cchar_t u; // unicode
#endif
} chcc_u;

typedef struct symb_color {
  chcc_u c;
  short pair;
  const short color;
} symb_color_s;

typedef struct symb_item {
  symb_color_s sc;
  double factor;
  int scale;
} symb_item_s;

uint chart_mode;         // 1st and 2nd bits are in use, 3rd is reserved
uint chart_mode_max = 3;

//

static bool color_ready;

static symb_color_s map1[] = { // 2 intervals
  {.c.a = '.', .color = COLOR_WHITE },
  {.c.a = '>', .color = COLOR_YELLOW},
};

static symb_item_s map2[] = { // 8 intervals
  {.sc = {.c.a = '.',          .color = COLOR_WHITE  }},
  {.sc = {.c.a = '1',          .color = COLOR_GREEN  }},
  {.sc = {.c.a = '2',          .color = COLOR_CYAN   }},
  {.sc = {.c.a = '3',          .color = COLOR_BLUE   }},
  {.sc = {.c.a = 'a',          .color = COLOR_YELLOW }},
  {.sc = {.c.a = 'b',          .color = COLOR_MAGENTA}},
  {.sc = {.c.a = 'c',          .color = COLOR_RED    }},
  {.sc = {.c.a = '>' | A_BOLD, .color = COLOR_RED    }},
};

static struct {symb_color_s unsent, unkn;} chmap_na = {
  .unsent = {.c.a = ' '},
  .unkn   = {.c.a = '?' | A_BOLD, .color = COLOR_RED},
};

#ifdef WITH_UNICODE
static symb_item_s map3m[] = { // monocolor: 8 intervals
  {.sc = {.c.u    .CCHAR_chars = L"▁"}},
  {.sc = {.c.u    .CCHAR_chars = L"▂"}},
  {.sc = {.c.u    .CCHAR_chars = L"▃"}},
  {.sc = {.c.u    .CCHAR_chars = L"▄"}},
  {.sc = {.c.u    .CCHAR_chars = L"▅"}},
  {.sc = {.c.u    .CCHAR_chars = L"▆"}},
  {.sc = {.c.u    .CCHAR_chars = L"▇"}},
  {.sc = {.c.u = {.CCHAR_chars = {'>'}, .CCHAR_attr = A_BOLD}}},
};

static symb_item_s map3c[] = { // multicolor: 10 intervals
  {.sc = {.c.u    .CCHAR_chars = L"▂",                         .color = COLOR_GREEN }},
  {.sc = {.c.u    .CCHAR_chars = L"▄",                         .color = COLOR_GREEN }},
  {.sc = {.c.u    .CCHAR_chars = L"▆",                         .color = COLOR_GREEN }},
  {.sc = {.c.u    .CCHAR_chars = L"▁",                         .color = COLOR_YELLOW}},
  {.sc = {.c.u    .CCHAR_chars = L"▃",                         .color = COLOR_YELLOW}},
  {.sc = {.c.u    .CCHAR_chars = L"▅",                         .color = COLOR_YELLOW}},
  {.sc = {.c.u    .CCHAR_chars = L"▇",                         .color = COLOR_YELLOW}},
  {.sc = {.c.u    .CCHAR_chars = L"▂",                         .color = COLOR_RED   }},
  {.sc = {.c.u    .CCHAR_chars = L"▄",                         .color = COLOR_RED   }},
  {.sc = {.c.u    .CCHAR_chars = L"▆",                         .color = COLOR_RED   }},
  {.sc = {.c.u = {.CCHAR_chars = {'>'}, .CCHAR_attr = A_BOLD}, .color = COLOR_RED   }},
};

static struct {symb_color_s unsent, unkn;} ccmap_na = {
  .unsent = {.c.u    .CCHAR_chars = {' '}},
  .unkn   = {.c.u = {.CCHAR_chars = {'?'}, .CCHAR_attr = A_BOLD},
             .color = COLOR_RED},
};
#endif


// local
//

static inline bool monocolor(void) { return !color_ready || !run_opts.color; }

static void scale_map(uint len, symb_item_s map[len], uint at) NONNULL(2);
static void scale_map(uint len, symb_item_s map[len], uint at) {
  int minval = INT_MAX;
  int maxval = -1;
  uint max = net_max();
  for (; at < max; at++) {
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
  if ((maxval >= 0) && (minval <= maxval)) {
    int range = maxval - minval;
    for (uint i = 0; i < len; i++)
      map[i].scale = minval + range * map[i].factor;
  }
}

static inline void printw_msec(WINDOW *win, int width, double value) NONNULL(1);
static inline void printw_msec(WINDOW *win, int width, double value) {
  wprintw(win, "%.*f ", width, value);
  waddstr(win, MSEC_STR);
}

static inline int addch_un(WINDOW *win, chtype ch, bool mono) NONNULL(1);
static inline int addch_un(WINDOW *win, chtype ch, bool mono) {
  return waddch(win, mono ? (ch & ~A_COLOR) : ch);
}

#ifdef WITH_UNICODE
static inline int addcc_un(WINDOW *win, cchar_t *cc, bool mono) NONNULL(1, 2);
static inline int addcc_un(WINDOW *win, cchar_t *cc, bool mono) {
  if (mono)
    cc->CCHAR_attr &= ~A_COLOR;
  return wadd_wch(win, cc);
}
#endif

#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);

static void print_map1(WINDOW *win, bool mono) NONNULL(1);
static void print_map1(WINDOW *win, bool mono) {
  waddstr(win, "  ");
  waddch(win, map1[0].c.a | A_BOLD);
  int scale = map2[ARRAY_LEN(map2) - 2].scale;
  LENVALMIL(scale);
  if (scale > 0) {
    waddch(win, ' '); waddstr(win, LESSTHAN_STR); waddch(win, ' ');
    printw_msec(win, _l, _v);
  }
  waddstr(win, "   ");
  addch_un(win, map1[1].c.a, mono);
  if (scale > 0) {
    waddch(win, ' '); waddstr(win, MORETHAN_STR); waddch(win, ' ');
    printw_msec(win, _l, _v);
  }
  waddstr(win, "   ");
  addch_un(win, chmap_na.unkn.c.a, mono);
  if (scale > 0) {
    waddch(win, ' '); waddstr(win, UNKNOWN_STR);
  }
}

static void print_chmap(WINDOW *win, uint len, symb_item_s map[len], bool mono) NONNULL(1, 3);
static void print_chmap(WINDOW *win, uint len, symb_item_s map[len], bool mono) {
  for (uint i = 0; i < (len - 1); i++) {
    waddstr(win, "  ");
    addch_un(win, map[i].sc.c.a, mono);
    if (map[i].scale > 0) {
      waddch(win, ':');
      LENVALMIL(map[i].scale);
      printw_msec(win, _l, _v);
    }
  }
  waddstr(win, "  ");
  addch_un(win, map[len - 1].sc.c.a, mono);
}

#ifdef WITH_UNICODE
static void print_ccmap(WINDOW *win, uint len, symb_item_s map[len], bool mono) NONNULL(1, 3);
static void print_ccmap(WINDOW *win, uint len, symb_item_s map[len], bool mono) {
  for (uint i = 0; i < (len - 1); i++) {
    waddstr(win, "  ");
    addcc_un(win, &map[i].sc.c.u, mono);
    int scale = map[i].scale;
    if (scale > 0) {
      LENVALMIL(scale);
      waddch(win, ':');
      printw_msec(win, _l, _v);
    }
  }
  waddstr(win, "  ");
  addcc_un(win, &map[len - 1].sc.c.u, mono);
}
#endif

static void factor_init(uint len, symb_item_s map[len]) NONNULL(2);
static void factor_init(uint len, symb_item_s map[len]) {
  for (uint i = 0; i < len; i++) {
    double f = (i + 1) / (double)len;
    map[i].factor = f * f;
  }
}

static void mode12_colors(void) {
  if (chmap_na.unkn.pair)
    chmap_na.unkn.c.a |= COLOR_PAIR(chmap_na.unkn.pair);
  // display mode 1
  for (uint i = 0; i < ARRAY_LEN(map1); i++)
    if (map1[i].pair > 0)
      map1[i].c.a |= COLOR_PAIR(map1[i].pair);
  // display mode 2
  for (uint i = 0; i < ARRAY_LEN(map2); i++) {
    symb_color_s *sc = &map2[i].sc;
    if (sc->pair > 0)
      sc->c.a |= COLOR_PAIR(sc->pair);
  }
}

#ifdef WITH_UNICODE
static void mode3_colors(void) {
  if (ccmap_na.unkn.pair)
    ccmap_na.unkn.c.u.CCHAR_attr |= COLOR_PAIR(ccmap_na.unkn.pair);
  // display mode 3
  for (uint i = 0; i < ARRAY_LEN(map3c); i++) {
    symb_color_s *sc = &map3c[i].sc;
    if (sc->pair > 0)
      sc->c.u.CCHAR_attr |= COLOR_PAIR(sc->pair);
  }
}
#endif

static short pair_symb(short pair, short bg, symb_color_s *sc) NONNULL(3);
static short pair_symb(short pair, short bg, symb_color_s *sc) {
  if (sc->color >= 0) {
    bool okay = (init_pair(pair, sc->color, bg) == OK);
    if (okay)
      sc->pair = pair++;
    LOGMSG("init_pair(pair=%d, fg=%d, bg=%d) %s",
      okay ? sc->pair : pair, sc->color, bg, okay ? "okay" : "failed");
  }
  return pair;
}

static short pair_colors(short pair, short bg, uint len, symb_color_s map[len]) NONNULL(4);
static short pair_colors(short pair, short bg, uint len, symb_color_s map[len]) {
  for (uint i = 0; i < len; i++)
    pair = pair_symb(pair, bg, &map[i]);
  return pair;
}

static short pair_mapitems(short pair, short bg, uint len, symb_item_s map[len]) NONNULL(4);
static short pair_mapitems(short pair, short bg, uint len, symb_item_s map[len]) {
  for (uint i = 0; i < len; i++)
    pair = pair_symb(pair, bg, &map[i].sc);
  return pair;
}

static chtype mapped_ch(int value) {
  if (value == CT_UNSENT)
    return chmap_na.unsent.c.a;
  if ((value == CT_UNKN) || (value == CT_SEAL))
    return chmap_na.unkn.c.a;
  //
  if (chart_mode == 1)
    return map1[(value <= map2[ARRAY_LEN(map2) - 2].scale) ? 0 : 1].c.a;
  if (chart_mode == 2)
    for (uint i = 0; i < ARRAY_LEN(map2); i++)
      if (value <= map2[i].scale)
        return map2[i].sc.c.a;
  return chmap_na.unkn.c.a;
}

#ifdef WITH_UNICODE
static cchar_t* mapped_cc(int value) {
  bool mono = monocolor();
  if (value == CT_UNSENT)
    return &ccmap_na.unsent.c.u;
  if ((value == CT_UNKN) || (value == CT_SEAL))
    return &ccmap_na.unkn.c.u;
  uint len         = mono ? ARRAY_LEN(map3m) : ARRAY_LEN(map3c);
  symb_item_s *map = mono ?            map3m : map3c;
  for (uint i = 0; i < len; i++)
    if (value <= map[i].scale)
      return &map[i].sc.c.u;
  return &ccmap_na.unkn.c.u;
}
#endif


// global
//

short color_charts(void) {
  short pair = 1, rc = -1, fg = COLOR_WHITE, bg = COLOR_BLACK;
#ifdef HAVE_USE_DEFAULT_COLORS
  if (use_default_colors() == OK)
    fg = bg = -1;
#endif
  color_ready = has_colors() && can_change_color();
  //
  if (color_ready) {
    pair = pair_colors  (pair, bg, ARRAY_LEN(map1), map1); // display mode 1
    pair = pair_mapitems(pair, bg, ARRAY_LEN(map2), map2); // display mode 2
    pair = pair_symb(pair, bg, &chmap_na.unkn);
#ifdef WITH_UNICODE
    pair = pair_mapitems(pair, bg, ARRAY_LEN(map3c), map3c); // display mode 3
    pair = pair_symb(pair, bg, &ccmap_na.unkn);
#endif
    //
    if (tuilook == NEWLOOK) {
#define MIN_BG_COLORS 16
#define BG_LUM 150
#define DEF_BGCOL COLOR_BLACK
      if (COLORS > MIN_BG_COLORS) {
        const short shift = BG_LUM;
        short r = -1, g = -1, b = -1;
        if (color_content(DEF_BGCOL, &r, &g, &b) == OK) {
          double luma = 0.299 * r + 0.587 * g + 0.114 * b;
          if (luma > 500) { // light, make it darker
            r -= shift; if (r < 0) r = 0;
            g -= shift; if (g < 0) g = 0;
            b -= shift; if (b < 0) b = 0;
          } else {          // dark, make it lighter
            r += shift; if (r > 1000) r = 1000;
            g += shift; if (g > 1000) g = 1000;
            b += shift; if (b > 1000) b = 1000;
          }
          short bgcol = MIN_BG_COLORS;
          if ((init_color(bgcol, r, g, b) == OK) &&
              (init_pair(pair, fg, bgcol) == OK)) {
            rc = pair++;
            LOGMSG("contrast background RGB: %d, %d, %d", r, g, b);
          }
        }
      } else
        LOGMSG("%s", "not enough colors for contrast menu/status");
    }
  } else
    LOGMSG("%s", "no colors");
  return rc;
}

void prepare_charts(void) {
  // display mode: 1, 2
  if (!map2[0].factor)
    factor_init(ARRAY_LEN(map2), map2);
  mode12_colors();
#ifdef WITH_UNICODE
  // display mode: 3
  if (!map3m[0].factor)
    factor_init(ARRAY_LEN(map3m), map3m);
  if (!map3c[0].factor)
    factor_init(ARRAY_LEN(map3c), map3c);
  mode3_colors();
#endif
}

void chart_scale(uint offset) {
#ifdef WITH_UNICODE
  if (chart_mode == 3) { // display mode: 3
    if (monocolor())
      scale_map(ARRAY_LEN(map3m), map3m, offset);
    else
      scale_map(ARRAY_LEN(map3c), map3c, offset);
  } else                 // display modes: 1, 2
#endif
    scale_map(ARRAY_LEN(map2), map2, offset);
}

void print_scale(WINDOW *win) { // NONNULL(1);
  wattron(win, A_BOLD);
  waddstr(win, SCALE_STR);
  waddch(win, ':');
  wattroff(win, A_BOLD);
  bool mono = monocolor();
  if      (chart_mode == 1)
    print_map1(win, mono);
  else if (chart_mode == 2)
    print_chmap(win, ARRAY_LEN(map2), map2, mono);
#ifdef WITH_UNICODE
  else if (chart_mode == 3) {
    if (mono)
      print_ccmap(win, ARRAY_LEN(map3m), map3m, mono);
    else
      print_ccmap(win, ARRAY_LEN(map3c), map3c, mono);
  }
#endif
}

void chart_area(WINDOW *win, uint len, int saved[len]) { // NONNULL(1, 3)
  bool mono = monocolor();
#ifdef WITH_UNICODE
  if (chart_mode == 3)
    for (uint i = 0; i < len; i++)
      addcc_un(win, mapped_cc(saved[i]), mono);
  else
#endif
    for (uint i = 0; i < len; i++)
      addch_un(win, mapped_ch(saved[i]), mono);
}

void chart_range_loop(void) {
  uint mode = (chart_mode + 1) % chart_mode_max;
#ifdef USE_COLOR
  if (!mode) {
    if (!nocolor) {
      LOGMSG("toggle color bit: %d -> %d", run_opts.color, !run_opts.color);
      run_opts.color = !run_opts.color;
      if (run_opts.color)
        mode++;
    }
  }
#endif
  LOGMSG("switch display mode [opt.color=%d]: %d -> %d", run_opts.color, chart_mode, mode);
  chart_mode = mode;
  run_opts.chart = mode & 3; // chart bits
  OPT_SUM(chart);
}

