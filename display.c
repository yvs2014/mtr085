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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "config.h"
#include "mtr.h"
#include "display.h"
#ifdef CURSES
#include "mtr-curses.h"
#endif
#include "report.h"
#include "select.h"
#include "dns.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif
#ifdef GRAPHCAIRO
#include "graphcairo-mtr.h"
#endif
#ifdef SPLITMODE
#include "split.h"
#endif

void display_detect(int *argc, char ***argv) {
  display_mode = DisplayReport;
#ifdef CURSES
  display_mode = DisplayCurses;
#endif
}

void display_open(void) {
  switch (display_mode) {
  case DisplayReport:
    report_open();
    break;
#ifdef CURSES
  case DisplayCurses:
    mtr_curses_open();  
    break;
#endif
#ifdef SPLITMODE
  case DisplaySplit:
    split_open();
    break;
#endif
#ifdef GRAPHCAIRO
  case DisplayGraphCairo:
    if (!gc_open())
      exit(1);
    break;
#endif
  }
}

void display_close(bool notfirst) {
  switch (display_mode) {
  case DisplayReport:
    report_close(report_wide);
    break;
#ifdef OUTPUT_FORMAT_TXT
  case DisplayTXT:
    txt_close(notfirst);
    break;
#endif
#ifdef OUTPUT_FORMAT_CSV
  case DisplayCSV:
    csv_close(notfirst);
    break;
#endif
#ifdef OUTPUT_FORMAT_JSON
  case DisplayJSON:
    json_close(notfirst);
    break;
#endif
#ifdef OUTPUT_FORMAT_XML
  case DisplayXML:
    xml_close();
    break;
#endif
#ifdef CURSES
  case DisplayCurses:
    mtr_curses_close();
    break;
#endif
#ifdef SPLITMODE
  case DisplaySplit:
    split_close();
    break;
#endif
#ifdef GRAPHCAIRO
  case DisplayGraphCairo:
    gc_close();  
    break;
#endif
  }
}

void display_start(void) {
  switch (display_mode) {
#ifdef OUTPUT_FORMAT_JSON
  case DisplayJSON:
    json_head();
    break;
#endif
#ifdef OUTPUT_FORMAT_XML
  case DisplayXML:
    xml_head();
    break;
#endif
  }
}

void display_finish(void) {
  switch (display_mode) {
#ifdef OUTPUT_FORMAT_JSON
  case DisplayJSON:
    json_tail();
    break;
#endif
#ifdef OUTPUT_FORMAT_XML
  case DisplayXML:
    xml_tail();
    break;
#endif
  }
}

void display_redraw(void) {
  switch(display_mode) {
#ifdef CURSES
  case DisplayCurses:
    mtr_curses_redraw();
    break;
#endif
#ifdef SPLITMODE
  case DisplaySplit:
    split_redraw();
    break;
#endif
#ifdef GRAPHCAIRO
  case DisplayGraphCairo:
    gc_redraw();
    break;
#endif
  }
}

int display_keyaction(void) {
  switch(display_mode) {
#ifdef CURSES
  case DisplayCurses:
    return mtr_curses_keyaction();
#endif
#ifdef SPLITMODE
  case DisplaySplit:
    return split_keyaction();
#endif
  }
  return 0;
}

void display_loop(void) {
  switch(display_mode) {
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
  case DisplaySplit:
  case DisplayCurses:
#ifdef GRAPHCAIRO
  case DisplayGraphCairo:
#endif
    select_loop();
    break;
  }
}

void display_clear(void) {
#ifdef CURSES
  if (display_mode == DisplayCurses)
    mtr_curses_clear();
#endif
}
