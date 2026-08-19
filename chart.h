#ifndef CHART_H
#define CHART_H

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

#include "common.h"

short color_charts(void);
void prepare_charts(void);
void chart_scale(uint offset);
void print_scale(WINDOW *win) NONNULL(1);
void chart_area(WINDOW *win, uint len, int saved[len]) NONNULL(1, 3);
void chart_range_loop(void);

extern uint chart_mode;
extern uint chart_mode_max;

#endif
