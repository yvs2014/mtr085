#ifndef KIT_H
#define KIT_H

#include "common.h"
#include "inc.h"

void free_menukit(void);
void menu_handler(WINDOW *_win UNUSED);
void menu_updown(bool up);
void menu_toggle_look(void);
int  menu_form_key(int key);
//void menu_form_fin(void);
//
key_action_t menu_action(void);
bool inside_menu(int x, int y);
int mouse_select_n_toggle(void);
void set_kit_attr(const short *bg, const int *x0, const int *y0);
//void cursor_at_form(void);

extern bool menuactive;
extern int posted_form;
#define CURS_FORM 2

#endif
