#ifndef AUX_H
#define AUX_H

#include "common.h"

#define FLD_DEFAULT "LS NABWV"
#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);

char *trim(char *s);
int val2len(double v);

#ifdef CURSESMODE
void set_fld_active(const char *s);
bool is_custom_fld(void);
int limit_int(const int v0, const int v1, const int v, const char *it);
#endif
#if defined(CURSESMODE) || defined(GRAPHMODE)
void onoff_jitter(void);
#endif
const struct statf* active_statf(unsigned i);

extern unsigned fld_index[256];

#endif
