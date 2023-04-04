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

enum { ActionNone,  ActionQuit,  ActionReset,  ActionDisplay, 
  ActionClear, ActionPauseResume, ActionScrollDown, ActionScrollUp,
  ActionDNS, ActionTCP, ActionMPLS, ActionCache, ActionAS, ActionII };
enum { DisplayReport, DisplayCurses, DisplayRaw, DisplaySplit,
  DisplayTXT, DisplayCSV, DisplayJSON, DisplayXML, DisplayGraphCairo };

void display_detect(int *argc, char ***argv);
bool display_open(void);
void display_close(bool notfirst);
void display_redraw(void);
int display_keyaction(void);
void display_loop(void);
void display_clear(void);
void display_start(void);
void display_finish(void);

#endif
