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

#ifndef DISPLAY_H
#define DISPLAY_H

#include "common.h"

void display_start(uint n_targets UNUSED);
void display_final(void);
bool display_open(void);
void display_close(bool next);
void display_confirm_fin(void);

void display_loop(void);
extern void (*eachpass_fn)(void);
extern void (*dispreset_fn)(void);
extern void (*dispclear_fn)(void);
extern key_action_t (*keyaction_fn)(void);

#define EACHPASS do { if (eachpass_fn) eachpass_fn(); } while (0)
#define DISPRESET do { if (dispreset_fn) dispreset_fn(); } while (0)
#define DISPCLEAR do { if (dispclear_fn) dispclear_fn(); } while (0)

#endif
