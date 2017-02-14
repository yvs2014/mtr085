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

#include <netinet/in.h>

#include "config.h"

/* Don't put a trailing comma in enumeration lists. Some compilers 
   (notably the one on Irix 5.2) do not like that. */ 
enum { ActionNone,  ActionQuit,  ActionReset,  ActionDisplay, 
       ActionClear, ActionPauseResume, ActionMPLS, ActionDNS, ActionTCP,
#ifdef IPINFO
       ActionAS, ActionII, ActionII_Map,
#endif
       ActionScrollDown, ActionScrollUp  };
enum { DisplayReport, DisplayCurses,
#ifdef OUTPUT_FORMAT_CSV
       DisplayCSV,
#endif
#ifdef OUTPUT_FORMAT_RAW
       DisplayRaw,
#endif
#ifdef OUTPUT_FORMAT_TXT
       DisplayTXT,
#endif
#ifdef OUTPUT_FORMAT_XML
       DisplayXML,
#endif
#ifdef GRAPHCAIRO
       DisplayGraphCairo,
#endif
       DisplaySplit
};

/*  Prototypes for display.c  */
void display_detect(int *argc, char ***argv);
void display_open(void);
void display_close(time_t now);
void display_redraw(void);
int display_keyaction(void);
void display_loop(void);
void display_clear(void);

#endif
