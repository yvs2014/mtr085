#ifndef MACROS_H
#define MACROS_H

#include <err.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "config.h"

// common Unix parameters
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

// misc
#include "version.h"
#define MIL   1000
#define MICRO 1000000
#define NANO  1000000000
#define UNKN_ITEM "???"
#define GCDEBUG  // graphcairo output to console

// time conversions
#define time2msec(t) ((t).tv_sec * MIL + (t).tv_nsec / MICRO)
#define time2mfrac(t) ((t).tv_nsec % MICRO)
#define time2usec(t) ((t).tv_sec * MICRO + (t).tv_nsec / MIL)
#define mseccmp(a, b, CMP) (((a).ms == (b).ms) ? ((a).frac CMP (b).frac) : ((a).ms CMP (b).ms))
#define msec2float(a)        ((a).ms          + (a).frac              / (double)MICRO)
#define float_sub_msec(a, b) ((a).ms - (b).ms + ((a).frac - (b).frac) / (double)MICRO)

// just in case (usually defined in sys/time.h)
#ifndef timespecclear
#define timespecclear(t) ((t)->tv_sec = (t)->tv_nsec = 0)
#endif
#ifndef timespeccmp
#define timespeccmp(a, b, CMP)       \
  (((a)->tv_sec  ==  (b)->tv_sec)  ? \
   ((a)->tv_nsec CMP (b)->tv_nsec) : \
   ((a)->tv_sec  CMP (b)->tv_sec))
#endif
#ifndef timespecadd
#define timespecadd(a, b, s) do {             \
  (s)->tv_sec  = (a)->tv_sec  + (b)->tv_sec;  \
  (s)->tv_nsec = (a)->tv_nsec + (b)->tv_nsec; \
  if ((s)->tv_nsec >= NANO) {                 \
    ++(s)->tv_sec;                            \
    (s)->tv_nsec -= NANO;                     \
  }                                           \
} while (0)
#endif
#ifndef timespecsub
#define timespecsub(a, b, s) do {             \
  (s)->tv_sec  = (a)->tv_sec  - (b)->tv_sec;  \
  (s)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec; \
  if ((s)->tv_nsec < 0) {                     \
    --(s)->tv_sec;                            \
    (s)->tv_nsec += NANO;                     \
  }                                           \
} while (0)
#endif
//

/* C99 __func__, and two sets below to not detect ##/VA_OPT */

// warnings, errors
#define WARN(lit)         warn("%s: " lit, __func__)
#define WARN_(fmt, ...)   warn("%s: " fmt, __func__, __VA_ARGS__)
#define WARNX(lit)       warnx("%s: " lit, __func__)
#define WARNX_(fmt, ...) warnx("%s: " fmt, __func__, __VA_ARGS__)
#define ERRR(error, lit)        err(error, "%s: " lit, __func__)
#define ERRR_(error, fmt, ...)  err(error, "%s: " fmt, __func__, __VA_ARGS__)
#define ERRX(error, lit)       errx(error, "%s: " lit, __func__)
#define ERRX_(error, fmt, ...) errx(error, "%s: " fmt, __func__, __VA_ARGS__)
#define FAIL(lit)              errx(EXIT_FAILURE, "%s: " lit, __func__)
#define FAIL_(fmt, ...)        errx(EXIT_FAILURE, "%s: " fmt, __func__, __VA_ARGS__)

// logging
#ifdef LOGMOD
#include <syslog.h>
#define LOGMSG(lit)       syslog(LOG_PRIORITY, "%s: " lit, __func__)
#define LOGMSG_(fmt, ...) syslog(LOG_PRIORITY, "%s: " fmt, __func__, __VA_ARGS__)
#else
#define LOGMSG(lit)       {}
#define LOGMSG_(fmt, ...) {}
#endif
#define LOGRET(lit)           { LOGMSG(lit); return; }
#define LOGRET_(fmt, ...)     { LOGMSG_(fmt, __VA_ARGS__); return; }
#define LOG_RE(re, lit)       { LOGMSG(lit); return re; }
#define LOG_RE_(re, fmt, ...) { LOGMSG_(fmt, __VA_ARGS__); return re; }

#endif
