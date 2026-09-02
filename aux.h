#ifndef AUX_H
#define AUX_H

#include <stddef.h>
#include <limits.h>

#include "common.h"

#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);
#define INDENT_NUMB 4 // "NN. " length

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

long str2l(const char *arg);
int arg2int(int8_t opt, const char *arg, int min, int max,
  const char *what, char *buff, size_t size) NONNULL(2);
int ustrnlen(const char *str, int max);
int snprinte(char str[], size_t size, const char *format, ...);
char* fmt_datetime(time_t at, const char *fmt, size_t size, char buff[size]) NONNULL(2, 4);
char* datetime_c (time_t at, size_t size, char buff[size]) NONNULL(3);
char* datetime_FT(time_t at, size_t size, char buff[size]) NONNULL(3);

#ifdef USE_COLOR
void warnc(const char *fmt, ...);
void warnxc(const char *fmt, ...);
NORETURN void errc(int eval, const char *fmt, ...);
NORETURN void errxc(int eval, const char *fmt, ...);
#define WARNC  warnc
#define WARNXC warnxc
#define ERRC   errc
#define ERRXC  errxc
#else
#define WARNC  warn
#define WARNXC warnx
#define ERRC   err
#define ERRXC  errx
#endif

#ifdef WITH_MENU
void stat_keys(uint len, char buff[len]) NONNULL(2);
#endif

#endif
