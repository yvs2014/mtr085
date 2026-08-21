#ifndef TUI_INC_H
#define TUI_INC_H

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
#  error No *curses header
#endif

#if 0 /*not yet*/
#ifdef WITH_MENU
#if   defined(HAVE_NCURSESW_MENU_H)
#  include <ncursesw/menu.h>
#elif defined(HAVE_NCURSES_MENU_H)
#  include <ncurses/menu.h>
#elif defined(HAVE_MENU_H)
#  include <menu.h>
#else
#  error No menu header
#endif
#endif
#endif

#endif
