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

#ifndef MTR_CURSES_H
#define MTR_CURSES_H

/*  Prototypes for curses.c  */
void mtr_curses_open(void);
void mtr_curses_close(void);
void mtr_curses_redraw(void);
int mtr_curses_keyaction(void);
void mtr_curses_clear(void);

#define STARTSTAT	30
#ifdef GRAPHCAIRO
void mtr_curses_init(void);
void mtr_gen_scale_gc(void);
void mtr_curses_scale_desc(char *buf);
char mtr_curses_saved_ch(int saved_int);
int mtr_curses_data_fields(char *buf);
void mtr_fill_data(int at, char *buf, int sz);
#ifdef UNICODE
wchar_t mtr_curses_saved_wch(int saved_int);
#endif
#endif

#endif
