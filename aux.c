
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "aux.h"

#define FLOAT_UPTO 10 /* values > FLOAT_UPTO in integer format */

#ifdef CURSESMODE
static const char fld_jitter[MAXFLD + 1] = "DR AGJMXI";
#endif
static char fld_custom[MAXFLD + 1];

const char* fld_active;
unsigned fld_index[256] = {-1}; // key->index backresolv

inline int val2len(double v) { return ((v > 0) && (v < FLOAT_UPTO)) ? (v < 0.1 ? 2 : 1) : 0; }

char* trim(char *s) {
  char *p = s;
  int l = strlen(p);
  while (l && isspace((int)(p[l - 1]))) // order matters
    p[--l] = 0;
  while (isspace((int)*p))
    p++;
  return p;
}

void set_fld_active(const char *s) { strncpy(fld_custom, s, MAXFLD); fld_active = fld_custom; }
#ifdef CURSESMODE
bool is_custom_fld(void) { return strncmp(fld_active, fld_jitter, MAXFLD) && strncmp(fld_active, FLD_DEFAULT, MAXFLD); }
#endif
#if defined(CURSESMODE) || defined(GRAPHMODE)
void onoff_jitter(void) { int cmp = strncmp(fld_active, fld_jitter, MAXFLD); fld_active = cmp ? fld_jitter : fld_custom; }
#endif

const struct statf* active_statf(unsigned i) {
  if (i > MAXFLD) return NULL;
  unsigned n = fld_index[(uint8_t)fld_active[i]];
  return ((n >= 0) && (n < statf_max)) ? &statf[n] : NULL;
}

