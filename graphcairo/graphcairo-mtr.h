#ifndef GRAPHCAIRO_MTR_H
#define GRAPHCAIRO_MTR_H

#include <stdbool.h>

bool gc_open(void);
void gc_close(void);
bool gc_parsearg(char* arg);
void gc_redraw(void);
int gc_keyaction(void);

#endif
