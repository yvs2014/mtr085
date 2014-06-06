#ifndef GRAPHCAIRO_CURSES_H
#define GRAPHCAIRO_CURSES_H

void gc_curses_gen_scale(void);					// curses.c:434 mtr_gen_scale()
void gc_curses_init(void);						// curses.c:467 mtr_curses_init()
char gc_curses_saved_char(int i);
void gc_curses_set_legend(int max_cols, int sz, char *msg_top, char *msg_bottom);

#endif
