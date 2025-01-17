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
#define GITREV "204"
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

// options
typedef struct opts_s {
  bool
    interactive,
    //
    ips,      // -b
    mpls,     // -e
    jitter,   // -j
    asn,      // -l
    dns,      // -n
    pause,    // -p
    rawrep,   // -r (raw report mode)
    tcp,      // -t
    udp,      // -u
    oncache,  // -x
    ipinfo,   // -L
    endpoint, // -fa
    lookup,   // -l or -L
    stat,     // -S
    //
    bell,     // -d 7th bit (beep at target)
    visible,  // -d 6th bit (visible bell: flash)
    audible,  // -d 5th bit (beep)
    color;    // -d 4th bit (color mode)
  uint8_t
    chart,    // -d 1st and 2nd bits
    minttl,   // -f first_ttl
    maxttl,   // -m max_ttl
    qos;      // -q qos
  int
    cycles,   // -c cycles_to_run
    pattern,  // -b payload_pattern
    interval, // -i interval
    size,     // -s packet_size
    syn,      // -T tcp_timeout
    cache,    // -x
    port;     // port from 'target:port' in tcp/udp modes
} opts_t;

// options' cksum
typedef union opt_sum_u {
  unsigned un;
  unsigned
    interactive :1,
    //
    ips      :1, // -b
    mpls     :1, // -e
    jitter   :1, // -j
    asn      :1, // -l
    dns      :1, // -n
    pause    :1, // -p
    rawrep   :1, // -r (raw report mode)
    tcp      :1, // -t
    udp      :1, // -u
    oncache  :1, // -x
    ipinfo   :1, // -L
    endpoint :1, // -fa
    lookup   :1, // -l or -L
    stat     :1, // -S
    //
    bell     :1, // -d 7th bit (beep at target)
    visible  :1, // -d 6th bit (visible bell: flash)
    audible  :1, // -d 5th bit (beep)
    color    :1, // -d 4th bit (color mode)
    chart    :1, // -d 1st and 2nd bits
    //
    minttl   :1, // -f first_ttl
    maxttl   :1, // -m max_ttl
    qos      :1, // -q qos
    //
    pattern  :1, // -b payload_pattern
    cycles   :1, // -c cycles_to_run
    interval :1, // -i interval
    size     :1, // -s packet_size
    syn      :1, // -T tcp_timeout
    port     :1; // port from 'target:port' in tcp/udp modes
} opt_sum_t;

#define OPT_SUM(tag) do {opt_sum.tag = (run_opts.tag != ini_opts.tag);} while(0)

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

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

// externs
extern int mtrtype;        // default packet type

extern display_mode_t display_mode;

extern int sum_sock[];     // summary open()/close() calls for sockets
extern int last_neterr;    // last known network error ...
extern char err_fulltxt[]; // ... with this text

extern pid_t mypid;
extern char mtr_args[];
extern opts_t run_opts;    // runtime options
extern opts_t ini_opts;    // initial options
extern opt_sum_t opt_sum;  // checksum changes

#if defined(CURSESMODE) || defined(SPLITMODE)
extern int display_offset;
#endif
#ifdef CURSESMODE
extern int curses_mode;
extern int curses_mode_max;
#endif

// keys: the value in the array is the index number in statf[]
extern const char *fld_active;
extern const t_statf statf[];
extern const int statf_max;
enum { BLANK_INDICATOR = '_' };
//
extern char srchost[];
extern const char *dsthost;

#endif
