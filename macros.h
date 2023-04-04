#ifndef MACROS_H
#define MACROS_H

#include <err.h>
#include <stdlib.h>

// common Unix parameters
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

// misc
#include "version.h"
#define UNKN_ITEM "???"

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
