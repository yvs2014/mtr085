#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN  16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#define MAX_ADDRSTRLEN INET6_ADDRSTRLEN

// wrapper: __has_attribute
#ifndef __has_attribute
#define __has_attribute(attr) 0
#endif

#include "config.h"

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_STRLCPY
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#ifdef HAVE_BSD_STRING_H
#include <bsd/string.h>
#endif
// note: return size can distinct: src.len() and printed chars
#define STRLCPY(dst, src, size) strlcpy(dst, src, size)
#else
#define STRLCPY(dst, src, size) snprintf(dst, size, "%s", src)
#endif

#ifndef GITREV
#define GITREV "195"
#endif

typedef union inaddr_union {
  struct in_addr in;
  uint8_t s_addr8[4];
#ifdef ENABLE_IPV6
  struct in6_addr in6;
#endif
} t_ipaddr;

typedef union sockaddr_union {
  struct sockaddr     sa;
  struct sockaddr_in  sin;
#define SA_AF sa.sa_family
#define S_ADDR sin.sin_addr
#define S_PORT sin.sin_port
#ifdef ENABLE_IPV6
  struct sockaddr_in6 sin6;
#define S6ADDR sin6.sin6_addr
#define S6PORT sin6.sin6_port
#endif
} t_sockaddr;

// stat fields description
typedef struct statf {
  const char *name;
  const char *hint;
  int len;
  const char key;
} t_statf;

enum {
  MAXLABELS = 8, // mpls labels
  MAXFLD = 20,   // fields in custom set to display stats
  NAMELEN = 256,
};

typedef enum {
  DisplayAuto, // curses mode if available, otherwise split mode
  DisplayReport,
  DisplayCurses,
  DisplaySplit,
#ifdef OUTPUT_FORMAT_RAW
  DisplayRaw,
#endif
#ifdef OUTPUT_FORMAT_TXT
  DisplayTXT,
#endif
#ifdef OUTPUT_FORMAT_CSV
  DisplayCSV,
#endif
#ifdef OUTPUT_FORMAT_JSON
  DisplayJSON,
#endif
#ifdef OUTPUT_FORMAT_XML
  DisplayXML,
#endif
} display_mode_t;

typedef enum { ActionNone, ActionQuit, ActionReset, ActionDisplay,
  ActionClear, ActionPauseResume, ActionScrollDown, ActionScrollUp,
  ActionUDP, ActionTCP, ActionCache,
#ifdef WITH_MPLS
  ActionMPLS,
#endif
#ifdef ENABLE_DNS
  ActionDNS,
#endif
#ifdef WITH_IPINFO
  ActionAS, ActionII,
#endif
} key_action_t;

// misc
#define NOOP ((void)0)

#define MIL   1000
#define MICRO 1000000
#define NANO  1000000000
#define UNKN_ITEM "???"
#define AT_FMT "%2d."

#define SETBIT(a, n) do { (a) |= 1U << (n);    } while(0)
#define CLRBIT(a, n) do { (a) &= ~(1U << (n)); } while(0)
#define TGLBIT(a, n) do { (a) ^= 1U << (n);    } while(0)
#define CHKBIT(a, n) (((a) >> (n)) & 1U)
#define NEQBIT(a, b, n) (((a) ^ (b)) & (1U << (n)))


// logging, warnings, errors
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define LOG_PRIORITY LOG_NOTICE
#else
#define LOG_PRIORITY LOG_INFO
#endif
//
#ifdef LOGMOD
#include <syslog.h>
#else
#define LOGMSG(fmt, ...) ((void)0)
#define LOGRET(fmt, ...) return
#define LOG_RE(re, fmt, ...) return (re)
#endif
// note, VA_OPT min compat: gcc8, clang6
#if (__GNUC__ >= 8) || (__clang_major__ >= 6) || (__STDC_VERSION__ >= 202311L)
#define WARN(fmt, ...)   warn("%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define WARNX(fmt, ...) warnx("%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define ERRR(status, fmt, ...)  err(status, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define ERRX(status, fmt, ...) errx(status, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define FAIL(fmt, ...)         errx(EXIT_FAILURE, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#ifdef LOGMOD
#define LOGMSG(fmt, ...) syslog(LOG_PRIORITY, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define LOGMSG(fmt, ...) syslog(LOG_PRIORITY, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define LOGRET(fmt, ...) do { \
  syslog(LOG_PRIORITY, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__); return; } while(0)
#define LOG_RE(re, fmt, ...) do { \
  syslog(LOG_PRIORITY, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__); return (re); } while(0)
#endif
#else // no VA_OPT, use GNU extension
#define WARN(fmt, ...)   warn("%s: " fmt, __func__, ##__VA_ARGS__)
#define WARNX(fmt, ...) warnx("%s: " fmt, __func__, ##__VA_ARGS__)
#define ERRR(status, fmt, ...)  err(status, "%s: " fmt, __func__, ##__VA_ARGS__)
#define ERRX(status, fmt, ...) errx(status, "%s: " fmt, __func__, ##__VA_ARGS__)
#define FAIL(fmt, ...)         errx(EXIT_FAILURE, "%s: " fmt, __func__, ##__VA_ARGS__)
#ifdef LOGMOD
#define LOGMSG(fmt, ...) syslog(LOG_PRIORITY, "%s: " fmt, __func__, ##__VA_ARGS__)
#define LOGRET(fmt, ...) do { \
  syslog(LOG_PRIORITY, "%s: " fmt, __func__, ##__VA_ARGS__); return; } while(0)
#define LOG_RE(re, fmt, ...) do { \
  syslog(LOG_PRIORITY, "%s: " fmt, __func__, ##__VA_ARGS__); return (re); } while(0)
#endif
#endif // VA_OPT

// time conversions
#define time2msec(t) ((t).tv_sec * MIL + (t).tv_nsec / MICRO)
#define time2mfrac(t) ((t).tv_nsec % MICRO)
#define time2usec(t) ((t).tv_sec * MICRO + (t).tv_nsec / MIL)
#define mseccmp(a, b, CMP)  (((a).ms == (b).ms) ? ((a).frac CMP (b).frac) : ((a).ms CMP (b).ms))
#define msec2float(a)        ((a).ms          +  (a).frac             / (double)MICRO)
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

// externs
extern int mtrtype;        // default packet type

extern display_mode_t display_mode;
extern double wait_time;

extern int fstTTL;
extern int maxTTL;

extern bool hinit;         // make sure that a hashtable already exists or not
extern int remoteport;     // target port
extern int tos;            // type of service set in ping packet
extern bool endpoint_mode; // -fa option
extern bool cache_mode;    // don't ping known hops
extern int cache_timeout;  // cache timeout in seconds
extern int cbitpattern;    // payload bit pattern
extern int cpacketsize;    // default packet size, or user defined
extern int syn_timeout;    // timeout for TCP connections
extern int sum_sock[];     // summary open()/close() calls for sockets

extern int last_neterr;    // last known network error ...
extern char err_fulltxt[]; // ... with this text

extern pid_t mypid;
extern char mtr_args[];
// runtime args' bits
typedef enum { RA_NA = -1, // upto 32 [unsigned-in-bits]
  RA_UDP, RA_TCP, RA_MPLS, RA_ASN, RA_IPINFO, RA_DNS, RA_JITTER, RA_DM0, RA_DM1, RA_CACHE, RA_PAUSE,
  RA_CYCLE, RA_PATT, RA_MINTTL, RA_MAXTTL, RA_TOUT, RA_QOS, RA_SIZE, RA_MAX,
} ra_t;
extern unsigned run_args;   // runtime args to display hints
extern unsigned kept_args;  // kept args mapped in bits
  // bits:
  //   0 [u]: udp
  //   1 [t]: tcp
  //   2 [e]: mpls
  //   3 [z]: asn
  //   4 [y]: ipinfo
  //   5 [n]: dns
  //   6 [j]: jitter
  //   7 [d]: chart (4 modes: 2bits)
  //   8 [d]: -//-
  //   9 [x]: cache
  //  10 [p]: pause

#ifdef WITH_MPLS
extern bool enable_mpls;
#endif
#ifdef ENABLE_DNS
extern bool show_ips;
#endif
#if defined(CURSESMODE) || defined(SPLITMODE)
extern int display_offset;
#endif
#ifdef CURSESMODE
extern int curses_mode;
extern int curses_mode_max;
extern bool enable_color;
extern bool bell_audible;
extern bool bell_visible;
extern bool bell_target;
#endif

// keys: the value in the array is the index number in statf[]
extern const char *fld_active;
extern const t_statf statf[];
extern const int statf_max;
enum { BLANK_INDICATOR = '_' };
//
extern char srchost[];
extern const char *dsthost;
extern bool interactive;
extern long max_ping;

#endif
