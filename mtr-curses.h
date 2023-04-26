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

#include "config.h"

#ifdef WITH_UNICODE
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#endif

bool mc_open(void);
void mc_close(void);
void mc_redraw(void);
int mc_keyaction(void);
void mc_clear(void);

#define STARTSTAT	30
#ifdef GRAPHMODE
void mc_init(void);
int mc_statf_title(char *buf, int sz);
int mc_print_at(int at, char *buf, int sz);
int mc_snprint_args(char *buf, int sz);
#endif

#endif
