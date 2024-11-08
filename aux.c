
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "aux.h"
#include "common.h"

#ifndef HAVE_STRLCPY
#include <stdio.h>
#endif

static const double float_upto = 10;
static const double float_dec2 = 0.1;

#ifdef CURSESMODE
static const char fld_default[MAXFLD + 1] = "LS_NABWV";
static const char fld_jitter[MAXFLD + 1] = "DR_AGJMXI";
#endif
static char fld_custom[MAXFLD + 1];

const char* fld_active;
unsigned fld_index[UCHAR_MAX + 1] = {-1}; // key->index backresolv

inline int val2len(double val) { return ((val > 0) && (val < float_upto)) ? (val < float_dec2 ? 2 : 1) : 0; }

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

const struct statf* active_statf(unsigned nth) {
  if (nth > sizeof(fld_index)) return NULL;
  unsigned ndx = fld_index[(uint8_t)fld_active[nth]];
  return ((ndx >= 0) && (ndx < statf_max)) ? &statf[ndx] : NULL;
}

