#ifndef KIT_H
#define KIT_H

#include "attr.h"
#include "common.h"
#include "inc.h" // IWYU pragma: keep

typedef enum {
  KITMENU_NONE   = -1,
  KITMENU_MAIN   =  0,
  KITMENU_CYCLES =  1,
  KITMENU_BPATT  =  2,
  KITMENU_XCACHE =  3,
} menu_ndx_t;

void free_menus(void);
bool menu_active(void);
void menu_showup(WINDOW *_win UNUSED);
void menu_toggle_look(void);
void menu_inout(int key);
void menu_line_updown(bool up);
void menu_page_updown(int lines);
int  menu_form_key(int key);
//
key_action_t menu_action(void);
menu_ndx_t inside_curr_menu(int x, int y);
int mouse_select_n_toggle(menu_ndx_t ndx);
void set_kit_attr(const short *bg, const int *x0, const int *y0);
//void cursor_at_form(void);

extern int posted_form;
#define CURS_FORM 2

#endif
