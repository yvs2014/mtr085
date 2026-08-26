#ifndef MENUPAN_H
#define MENUPAN_H

#include "common.h"
#include "inc.h"

void free_menupan(void);
void menu_handler(WINDOW *_win UNUSED);
void menu_updown(bool up);
void menu_toggle_look(void);
key_action_t menu_action(void);
bool inside_menu(int x, int y);

extern bool menuactive;
extern short menu_bg;

#endif
