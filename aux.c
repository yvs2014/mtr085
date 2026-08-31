
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <stdarg.h>

#include "aux.h"

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

#if defined(TUIMODE) || defined(SPLITMODE)
#define NOT_JITTER_FLD  STR_NEQ(fld_active, fld_jitter,  sizeof(fld_jitter))
#define NOT_DEFAULT_FLD STR_NEQ(fld_active, fld_default, sizeof(fld_default))
void onoff_jitter(void) { fld_active = NOT_JITTER_FLD ? fld_jitter : fld_custom; }
#endif

#ifdef TUIMODE
bool is_custom_fld(void) { return NOT_JITTER_FLD && NOT_DEFAULT_FLD; }
#endif

const t_stat* active_stats(size_t nth) {
  if (!fld_active || (nth > MAXFLD))
    return NULL;
  int ndx = fld_index[(uint8_t)fld_active[nth]];
  return ((ndx >= 0) && (ndx < stat_max)) ? &stats[ndx] : NULL;
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

int arg2int(int8_t opt, const char *arg, int min, int max, // NONNULL(2)
  const char *what, char *buff, size_t size)
{
// in buff (opt == 0)
// opt < 0: warn() on error
// opt > 0: err()  on error
  bool inbuf = buff && size;
  if (inbuf)
    buff[0] = 0;
  long value = str2l(arg);
  if ((value < min) || (value > max)) {
    value = (value < min) ? min : max;
    errno = ERANGE;
    WHATARG_BUFFERR("%.20s: %s [%d,%d]", arg, strerror(errno), min, max);
  } else if (errno) {
    WHATARG_BUFFERR("%s", strerror(errno));
  }
  // keep errno for "opt < 0 (warn)" case only, otherwise clean
  if (opt >= 0)
    errno = 0;
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
        if (len >= max)
          break;
        len++;
      }
  return len;
}

char* fmt_datetime(time_t at, const char *fmt, size_t size, char buff[size]) { // NONNULL(2, 4)
  if (!size)
    return NULL;
  buff[0] = 0;
#ifdef HAVE_LOCALTIME_R
  struct tm re;
  struct tm *tm = (at > 0) ? localtime_r(&at, &re) : NULL;
#else
  struct tm *tm = (at > 0) ? localtime(&at) : NULL;
#endif
  if (tm && !strftime(buff, size, fmt, tm))
    buff[0] = 0;
  return buff;
}

inline char* datetime_c(time_t at, size_t size, char buff[size]) { // NONNULL(3)
  return fmt_datetime(at, "%c", size, buff);
}

inline char* datetime_FT(time_t at, size_t size, char buff[size]) { // NONNULL(3)
  return fmt_datetime(at, "%F %T", size, buff);
}

int snprinte(char str[], size_t size, const char *format, ...) {
  if (!str || !size || !format)
    return 0;
  va_list args;
  va_start(args, format);
  int len = vsnprintf(str, size, format, args);
  va_end(args);
  if (len >= (int)size)
    len = -1; // truncation as error
  if (len < 0)
    str[0] = 0;
  return len;
}

void stat_keys(uint len, char buff[len]) { // NONNULL(2)
  for (uint i = 0; i < len; i++)
    buff[i] = ((int)i < stat_max) ? stats[i].key : 0;
}

