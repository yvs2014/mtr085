#ifndef AUX_H
#define AUX_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"

#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);

char* trim(char *str);
int val2len(double val);

extern int fld_index[UCHAR_MAX + 1];
void set_fld_active(const char *str);
#ifdef CURSESMODE
bool is_custom_fld(void);
void onoff_jitter(void);
#endif
const struct statf* active_statf(size_t nth);

extern char limit_error[NAMELEN];
int limit_int(int min, int max, const char *arg, const char *what, int8_t fail);

#endif
