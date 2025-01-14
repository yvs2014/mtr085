
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

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

const struct statf* active_statf(size_t nth) {
  if (nth > sizeof(fld_index)) return NULL;
  int ndx = fld_index[(uint8_t)fld_active[nth]];
  return ((ndx >= 0) && (ndx < statf_max)) ? &statf[ndx] : NULL;
}

static inline long str2long(const char *arg) {
  char *end = NULL; errno = 0;
  long num = strtol(arg, &end, 10);
  if (errno || *end) {
    end = NULL; errno = 0;
    num = strtol(arg, &end, 16);
    if (!errno && *end)
      errno = EINVAL;
  }
  return num;
}

char limit_error[NAMELEN];
int limit_int(int min, int max, const char *arg, const char *what, int8_t fail) {
  limit_error[0] = 0;
  int val = str2long(arg);
  int lim = val;
  if (errno) {
    snprintf(limit_error, sizeof(limit_error), "%s", strerror(errno));
    lim = INT_MIN;
  }
  int len = 0;
  if (val < min) {
    errno = ERANGE;
    lim = min;
    len = snprintf(limit_error, sizeof(limit_error), "%s: less than %d: %s", what, min, arg);
  } else if (val > max) {
    errno = ERANGE;
    lim = max;
    len = snprintf(limit_error, sizeof(limit_error), "%s: greater than %d: %s", what, max, arg);
  }
  if (val != lim) {
    if (fail > 0) {
      warnx("%s", limit_error);
      err(errno ? errno : EXIT_FAILURE, "-%c option failed", fail);
    } else if (fail < 0) {
      warnx("%s", limit_error);
    } else {
      if (len < 0)
        len = 0;
      snprintf(limit_error + len, sizeof(limit_error) - len,
        ", corrected(%d -> %d)", val, lim);
    }
  }
  return lim;
}

