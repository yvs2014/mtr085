#ifndef AUX_H
#define AUX_H

#include "common.h"

#ifdef VERSION
#ifdef GITREV
#define FULLNAME PACKAGE_NAME "-" VERSION "." GITREV
#else
#define FULLNAME PACKAGE_NAME "-" VERSION
#endif
#else
#define FULLNAME PACKAGE_NAME
#endif

#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);

char* trim(char *s);
int val2len(double v);

void set_fld_active(const char *s);
#ifdef CURSESMODE
bool is_custom_fld(void);
extern char limit_error[];
int limit_int(int min, int max, int val, const char *what, char fail);
#endif
#if defined(CURSESMODE) || defined(GRAPHMODE)
void onoff_jitter(void);
#endif
const struct statf* active_statf(unsigned i);

extern unsigned fld_index[256];

#endif
