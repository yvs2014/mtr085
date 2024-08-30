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

#include <stdbool.h>

enum { ActionNone, ActionQuit, ActionReset, ActionDisplay,
  ActionClear, ActionPauseResume, ActionScrollDown, ActionScrollUp,
  ActionUDP, ActionTCP, ActionCache
#ifdef WITH_MPLS
  , ActionMPLS
#endif
#ifdef ENABLE_DNS
  , ActionDNS
#endif
#ifdef WITH_IPINFO
  , ActionAS, ActionII
#endif
};
enum { DisplayReport, DisplayCurses, DisplaySplit
#ifdef GRAPHMODE
  , DisplayGraphCairo
#endif
#ifdef OUTPUT_FORMAT_RAW
  , DisplayRaw
#endif
#ifdef OUTPUT_FORMAT_TXT
  , DisplayTXT
#endif
#ifdef OUTPUT_FORMAT_CSV
  , DisplayCSV
#endif
#ifdef OUTPUT_FORMAT_JSON
  , DisplayJSON
#endif
#ifdef OUTPUT_FORMAT_XML
  , DisplayXML
#endif
};

void display_start(void);
void display_final(void);
bool display_open(bool notfirst);
void display_close(bool notfirst);

void display_redraw(void);
void display_loop(void);
void display_clear(void);
int display_key_action(void);
int display_extra_action(void);

#endif
