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

#include "mtr-poll.h"
#include "common.h"
#include "report.h"
#include "display.h"
#ifdef CURSESMODE
#include "mtr-curses.h"
#endif
#ifdef SPLITMODE
#include "split.h"
#endif
#ifdef GRAPHMODE
#include "graphcairo-mtr.h"
#endif

bool display_open(bool notfirst) {
  switch (display_mode) {
    case DisplayReport: report_open(notfirst); break;
#ifdef CURSESMODE
    case DisplayCurses: return mc_open();
#endif
#ifdef SPLITMODE
    case DisplaySplit: split_open(); break;
#endif
#ifdef GRAPHMODE
    case DisplayGraphCairo: return gc_open();
#endif
  }
  return true;
}

void display_close(bool notfirst) {
  switch (display_mode) {
    case DisplayReport: report_close(report_wide); break;
#ifdef CURSESMODE
    case DisplayCurses: mc_close(); break;
#endif
#ifdef SPLITMODE
    case DisplaySplit: split_close(); break;
#endif
#ifdef GRAPHMODE
    case DisplayGraphCairo: gc_close(); break;
#endif
#ifdef OUTPUT_FORMAT_TXT
    case DisplayTXT: txt_close(notfirst); break;
#endif
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV: csv_close(notfirst); break;
#endif
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON: json_close(notfirst); break;
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML: xml_close(); break;
#endif
  }
}

void display_start(void) {
  if (display_mode < 0) {
#ifdef CURSESMODE
    display_mode = DisplayCurses; // default
#else
    display_mode = DisplayReport; // if no curses
#endif
  }
  switch (display_mode) {
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON: json_head(); break;
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML: xml_head(); break;
#endif
  }
}

void display_final(void) {
  switch (display_mode) {
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON: json_tail(); break;
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML: xml_tail(); break;
#endif
  }
}

void display_redraw(void) {
  switch(display_mode) {
#ifdef CURSESMODE
    case DisplayCurses: mc_redraw(); break;
#endif
#ifdef SPLITMODE
    case DisplaySplit: split_redraw(); break;
#endif
#ifdef GRAPHMODE
    case DisplayGraphCairo: gc_redraw(); break;
#endif
  }
}

int display_key_action(void) {
  switch(display_mode) {
#ifdef CURSESMODE
    case DisplayCurses: return mc_keyaction();
#endif
#ifdef SPLITMODE
    case DisplaySplit: return split_keyaction();
#endif
  }
  return ActionNone;
}

int display_extra_action(void) {
  return
#ifdef GRAPHMODE
    (display_mode == DisplayGraphCairo) ? gc_keyaction() :
#endif
    ActionNone;
}

void display_loop(void) {
  switch(display_mode) {
#ifdef CURSESMODE
    case DisplayCurses:
#endif
#ifdef SPLITMODE
    case DisplaySplit:
#endif
#ifdef GRAPHMODE
    case DisplayGraphCairo:
#endif
    case DisplayReport:
#ifdef OUTPUT_FORMAT_RAW
    case DisplayRaw:
#endif
#ifdef OUTPUT_FORMAT_TXT
    case DisplayTXT:
#endif
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV:
#endif
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON:
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
      poll_loop(); break;
  }
}

void display_clear(void) {
#ifdef CURSESMODE
  if (display_mode == DisplayCurses)
    mc_clear();
#endif
}

