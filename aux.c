
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>

#include "aux.h"
#include "common.h"

static const double float_upto = 10;
static const double float_dec2 = 0.1;

static const char fld_default[MAXFLD + 1] = "LS_NABWV";
static const char fld_jitter[MAXFLD + 1] = "DR_AGJMXI";
static char fld_custom[MAXFLD + 1];

const char* fld_active;
int fld_index[UCHAR_MAX + 1] = {-1}; // key->index backresolv

int val2len(double val) { return ((val > 0) && (val < float_upto)) ? (val < float_dec2 ? 2 : 1) : 0; }

char* trim(char *str) {
  if (str) {
    while (isspace((int)*str)) str++;
    if (*str) {
      char *end = str + strlen(str);
      char *ptr = end;
      while ((ptr != str) && isspace((int)*(--ptr)));
      if (++ptr < end) *ptr = 0;
    }
  }
  return str;
}

void set_fld_active(const char *str) {
  snprinte(fld_custom, sizeof(fld_custom), "%s", str ? str : fld_default);
  fld_active = fld_custom;
}
#ifdef TUIMODE
bool is_custom_fld(void) { return (strncmp(fld_active, fld_jitter, sizeof(fld_jitter)) != 0) && (strncmp(fld_active, fld_default, sizeof(fld_default)) != 0); }
#endif
#if defined(TUIMODE) || defined(SPLITMODE)
void onoff_jitter(void) { int cmp = strncmp(fld_active, fld_jitter, sizeof(fld_jitter)); fld_active = cmp ? fld_jitter : fld_custom; }
#endif

const t_stat* active_stats(size_t nth) {
  if (!fld_active || (nth > MAXFLD)) return NULL;
  int ndx = fld_index[(uint8_t)fld_active[nth]];
  return ((ndx >= 0) && (ndx < stat_max)) ? &stats[ndx] : NULL;
}

void foreach_stat(int at, void (*body)(int at, const t_stat *stat), char fin) {
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (stat) body(at, stat); else break;
  }
  if (fin) putchar(fin);
}

long str2l(const char *arg) {
  long num = 0;
  if (arg && *arg) {
    errno = 0; char *end = NULL;
    num = strtol(arg, &end, 0);
    if (!errno && ((end && *end) || (arg == end)))
      errno = EINVAL;
  } else
    errno = EINVAL;
  return num;
}

#define BUFWARNERR(fmt, ...) do {            \
  if (inbuf)                                 \
    snprinte(buff, size, fmt, __VA_ARGS__);  \
  else if (opt < 0)                          \
    warnx(               fmt, __VA_ARGS__);  \
  else                                       \
    errx(errno,          fmt, __VA_ARGS__);  \
} while(0)
//
#define OPTARG_BUFERR(fmt, ...) do {           \
  if (opt > 0)                                 \
    BUFWARNERR("-%c: " fmt, opt, __VA_ARGS__); \
  else                                         \
    BUFWARNERR(        fmt,      __VA_ARGS__); \
} while (0)
//
#define WHATARG_BUFFERR(fmt, ...) do {            \
  if (what && what[0])                            \
    OPTARG_BUFERR("%s: " fmt, what, __VA_ARGS__); \
  else                                            \
    OPTARG_BUFERR(       fmt,       __VA_ARGS__); \
} while (0)

int arg2int(int8_t opt, const char *arg, int min, int max, const char *what, char *buff, size_t size) {
// in buff (opt == 0)
// opt < 0: warn() on error
// opt > 0: err()  on error
  bool inbuf = buff && size;
  if (inbuf) buff[0] = 0;
  long value = str2l(arg);
  if ((value < min) || (value > max)) {
    value = (value < min) ? min : max;
    errno = ERANGE;
    WHATARG_BUFFERR("%.20s: %s [%d,%d]", arg, strerror(errno), min, max);
  } else if (errno) {
    WHATARG_BUFFERR("%s", strerror(errno));
  }
  // keep errno for "opt < 0 (warn)" case only, otherwise clean
  if (opt >= 0) errno = 0;
  return value;
}
#undef BUFWARNERR
#undef OPTARG_BUFERR
#undef WHATARG_BUFFERR

int ustrnlen(const char *str, int max) {
  // length in codepoints, 'int' to be signed
  int len = 0;
  if (str)
    for (; *str; str++)
      if ((*str & 0xc0) != 0x80) {
        if (len < max) len++; else break;
      }
  return len;
}

char *datetime(time_t at, char *buff, size_t size) {
  if (!size) return NULL;
  buff[0] = 0;
#ifdef HAVE_LOCALTIME_R
  struct tm re;
  struct tm *tm = (at > 0) ? localtime_r(&at, &re) : NULL;
#else
  struct tm *tm = (at > 0) ? localtime(&at) : NULL;
#endif
  if (tm)
    if (!strftime(buff, size, "%c", tm))
      buff[0] = 0;
  return buff;
}

int snprinte(char str[], size_t size, const char *format, ...) {
  if (!str || !format) return 0;
  va_list args;
  va_start(args, format);
  int len = vsnprintf(str, size, format, args);
  va_end(args);
  if (len >= (int)size) len = -1; // truncation as error
  if (len < 0) str[0] = 0;
  return len;
}

