#ifndef ACTION_H
#define ACTION_H

#include "common.h"
#include "inc.h"

key_action_t tui_actionw(WINDOW *win, void (*reset)(void)) NONNULL(1);
void status_no_crd(WINDOW *win, uint len, char buff[len]) NONNULL(1, 3);
#ifdef WITH_MOUSE
void status_n_keep_crd(WINDOW *win, uint len, char buff[len]) NONNULL(1, 3);
void topbar_icons(WINDOW *win) NONNULL(1);
void enable_mouse(void);
void disable_mouse(void);
#endif

extern uint display_offset;

#ifdef WITH_MENU
#define WREFRESH(win) menuactive ? update_panels() : (void)wnoutrefresh(win)
#else
#define WREFRESH(win) wnoutrefresh(win)
#endif

#endif
