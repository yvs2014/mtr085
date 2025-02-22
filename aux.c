
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include "aux.h"
#include "common.h"

static const double float_upto = 10;
static const double float_dec2 = 0.1;

#ifdef CURSESMODE
static const char fld_default[MAXFLD + 1] = "LS_NABWV";
static const char fld_jitter[MAXFLD + 1] = "DR_AGJMXI";
#endif
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

void set_fld_active(const char *str) { STRLCPY(fld_custom, str ? str : fld_default, sizeof(fld_custom)); fld_active = fld_custom; }
#ifdef CURSESMODE
bool is_custom_fld(void) { return (strncmp(fld_active, fld_jitter, sizeof(fld_jitter)) != 0) && (strncmp(fld_active, fld_default, sizeof(fld_default)) != 0); }
void onoff_jitter(void) { int cmp = strncmp(fld_active, fld_jitter, sizeof(fld_jitter)); fld_active = cmp ? fld_jitter : fld_custom; }
#endif

const t_stat* active_stats(size_t nth) {
  if (nth > sizeof(fld_index)) return NULL;
  int ndx = fld_index[(uint8_t)fld_active[nth]];
  return ((ndx >= 0) && (ndx < stat_max)) ? &stats[ndx] : NULL;
}

static inline long long str2ll(const char *arg) {
#define STR2L_FAILED (errno || (end && *end) || (arg == end))
  char *end = NULL; errno = 0;
  long long num = strtoll(arg, &end, 10);
  if (STR2L_FAILED) { // try hex
    end = NULL; errno = 0;
    num = strtoll(arg, &end, 16);
    if (STR2L_FAILED && !errno)
      errno = EINVAL;
  }
  return num;
#undef STR2L_FAILED
}

char limit_error[NAMELEN];
int limit_int(int min, int max, const char *arg, const char *what, int8_t fail) {
  limit_error[0] = 0;
  long long val = str2ll(arg);
  long long lim = val;
  if (errno)
    snprintf(limit_error, sizeof(limit_error), "%s", strerror(errno));
  if ((val < min) || (val > max)) {
    errno = ERANGE;
    lim = (val < min) ? min : max;
    snprintf(limit_error, sizeof(limit_error),
      "%s: %s: %s [%d,%d]", what, arg, strerror(errno), min, max);
  }
  if (errno && fail) {
    if (fail > 0) {
      limit_error[0] ?
        errx(errno ? errno : EXIT_FAILURE, "-%c: %s", fail, limit_error) :
        err (errno ? errno : EXIT_FAILURE, "-%c", fail);
    } else
      warnx("%s", limit_error);
  }
  return lim;
}

unsigned ustrlen(const char *str) {
  unsigned len = 0;
  if (str) for (; *str; str++) if ((*str & 0xc0) != 0x80) len++;
  return len;
}

char *datetime(time_t at, char *buff, size_t size) {
  if (!buff || !size) return NULL;
  buff[0] = 0;
#ifdef HAVE_LOCALTIME_R
  struct tm re;
  struct tm *tm = (at > 0) ? localtime_r(&at, &re) : NULL;
#else
  struct tm *tm = (at > 0) ? localtime(&at) : NULL;
#endif
  if (tm) strftime(buff, size, "%c", tm);
  return buff;
}

