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

#include "common.h"
#include "display.h"
#include "polling.h"
#include "report.h"
#ifdef TUIMODE
#include "tui.h"
#endif
#ifdef SPLITMODE
#include "split.h"
#endif

void (*eachpass_fn)(void);
void (*dispclear_fn)(void);
void (*dispreset_fn)(void);
key_action_t (*keyaction_fn)(void);

bool display_open(void) {
  switch (display_mode) {
#ifdef TUIMODE
    case DisplayTUI: return tui_open();
#endif
#ifdef SPLITMODE
    case DisplaySplit: split_open(); break;
#endif
    default: break;
  }
  return true;
}

void display_close(bool next) {
  switch (display_mode) {
    case DisplayReport: report_close(next, true); break;
#ifdef TUIMODE
    case DisplayTUI: tui_close(); break;
#endif
#ifdef SPLITMODE
    case DisplaySplit: split_close(); break;
#endif
#ifdef OUTPUT_FORMAT_TXT
    case DisplayTXT: report_close(next, false); break;
#endif
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV: csv_close(next); break;
#endif
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON: json_close(next); break;
#endif
#ifdef OUTPUT_FORMAT_TOON
    case DisplayTOON: toon_close(); break;
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML: xml_close(); break;
#endif
    default: break;
  }
}

static inline void display_set_callbacks(void) {
  switch (display_mode) {
#ifdef TUIMODE
    case DisplayTUI:
      keyaction_fn = tui_keyaction;
      dispreset_fn = tui_reset;
      dispclear_fn = tui_clear;
      eachpass_fn  = tui_redraw;
      break;
#endif
#ifdef SPLITMODE
    case DisplaySplit:
      keyaction_fn = split_keyaction;
      eachpass_fn  = split_redraw;
      break;
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
#ifdef OUTPUT_FORMAT_TOON
    case DisplayTOON:
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
    case DisplayReport:
#ifdef ENABLE_DNS
      eachpass_fn = backresolv_lookups;
#endif
      break;
    default: break;
  }
}

static inline void display_started_at(void) {
  switch (display_mode) {
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV:
#endif
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON:
#endif
#ifdef OUTPUT_FORMAT_TOON
    case DisplayTOON:
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
    case DisplayReport:
      report_started_at(); break;
    default: break;
  }
}

static inline void display_head_out(uint n_targets UNUSED) {
  switch (display_mode) {
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV: csv_head(); break;
#endif
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON: json_head(); break;
#endif
#ifdef OUTPUT_FORMAT_TOON
    case DisplayTOON: toon_head(n_targets); break;
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML: xml_head(); break;
#endif
    default: break;
  }
}

void display_start(uint n_targets UNUSED) {
  if (display_mode == DisplayAuto) {
#ifdef TUIMODE
    display_mode = DisplayTUI; // default
#else
    display_mode = DisplayReport; // if no curses
#endif
  }
  //
  display_set_callbacks();
  display_started_at();
  display_head_out(n_targets);
}

void display_confirm_fin(void) {
#ifdef TUIMODE
  if (display_mode == DisplayTUI) tui_confirm();
#endif
}

void display_final(void) {
  switch (display_mode) {
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON: json_tail(); break;
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML: xml_tail(); break;
#endif
    default: break;
  }
}

void display_loop(void) {
  switch (display_mode) {
#ifdef TUIMODE
    case DisplayTUI:
#endif
#ifdef SPLITMODE
    case DisplaySplit:
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
#ifdef OUTPUT_FORMAT_TOON
    case DisplayTOON:
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
      poll_loop(); break;
    default: break;
  }
}

