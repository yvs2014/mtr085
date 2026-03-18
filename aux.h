#ifndef AUX_H
#define AUX_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "common.h"

#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);

#if __has_attribute(unused)
#define UNUSED __attribute__((unused))
#else
#define UNUSED
#endif
#if __has_attribute(nonnull)
#define NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define NONNULL(...)
#endif

char* trim(char *str);
int val2len(double val);

extern int fld_index[UCHAR_MAX + 1];
void set_fld_active(const char *str);
#ifdef CURSESMODE
bool is_custom_fld(void);
void onoff_jitter(void);
#endif
const t_stat* active_stats(size_t nth);
void foreach_stat(int at, void (*body)(int at, const t_stat *stat), char fin) NONNULL(2);

extern char limit_error[NAMELEN];
int limit_int(int min, int max, const char *arg, const char *what, char fail) NONNULL(3);
uint ustrlen(const char *str);
char *datetime(time_t at, char *buff, size_t size) NONNULL(2);
int snprints(char str[], size_t size, const char *format, ...);

#endif
