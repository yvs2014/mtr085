#ifndef AUX_H
#define AUX_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "common.h"

#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);

char* trim(char *str);
int val2len(double val);

extern int fld_index[UCHAR_MAX + 1];
void set_fld_active(const char *str);
#ifdef TUIMODE
bool is_custom_fld(void);
#endif
#if defined(TUIMODE) || defined(SPLITMODE)
void onoff_jitter(void);
#endif
const t_stat* active_stats(size_t nth);
void foreach_stat(int at, void (*body)(int at, const t_stat *stat), char fin) NONNULL(2);

int arg2int(char opt, const char *arg, int min, int max,
  const char *what, char *buff, size_t size) NONNULL(2);
int ustrnlen(const char *str, int max);
char *datetime(time_t at, char *buff, size_t size) NONNULL(2);
int snprinte(char str[], size_t size, const char *format, ...);

#endif
