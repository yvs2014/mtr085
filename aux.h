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

char* trim(char *str);
int val2len(double val);

void set_fld_active(const char *str);
#ifdef CURSESMODE
bool is_custom_fld(void);
extern char limit_error[NAMELEN];
int limit_int(int min, int max, int val, const char *what, char fail);
void onoff_jitter(void);
#endif
const struct statf* active_statf(unsigned nth);

extern unsigned fld_index[UCHAR_MAX + 1];

#endif
