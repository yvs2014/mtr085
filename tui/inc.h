#ifndef TUI_INC_H
#define TUI_INC_H

#if !defined(_XOPEN_SOURCE_EXTENDED) && !(defined(_XOPEN_SOURCE) && (_XOPEN_SOURCE - 0 >= 500))
#  define _XOPEN_SOURCE_EXTENDED
#endif

#ifdef WITH_UNICODE
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

#ifdef WITH_MENU
#  if   defined(HAVE_NCURSESW_MENU_H)
#    include <ncursesw/menu.h>
#  elif defined(HAVE_NCURSES_MENU_H)
#    include <ncurses/menu.h>
#  elif defined(HAVE_MENU_H)
#    include <menu.h>
#  else
#    error No menu-header
#  endif
//
#  if   defined(HAVE_NCURSESW_PANEL_H)
#    include <ncursesw/panel.h>
#  elif defined(HAVE_NCURSES_PANEL_H)
#    include <ncurses/panel.h>
#  elif defined(HAVE_PANEL_H)
#    include <panel.h>
#  else
#    error No panel-header
#  endif
//
#  if   defined(HAVE_NCURSESW_FORM_H)
#    include <ncursesw/form.h>
#  elif defined(HAVE_NCURSES_FORM_H)
#    include <ncurses/form.h>
#  elif defined(HAVE_FORM_H)
#    include <form.h>
#  else
#    error No form-header
#  endif
#endif

#endif
