#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <err.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN  16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#define MAX_ADDRSTRLEN INET6_ADDRSTRLEN

#ifndef GITREV
#define GITREV "331"
#endif

#ifndef HAVE_UINT
typedef unsigned int uint;
#endif
#ifndef HAVE_ULONG
typedef unsigned long int ulong;
#endif

#define STR_EQ(a, b, n) (!strncmp((a), (b), n))
#define STR_NEQ(a, b, n) (strncmp((a), (b), n))

#ifdef IP_TOS
  #ifndef ENABLE_QOS4
    #define ENABLE_QOS4
  #endif
#endif
#if defined(ENABLE_IPV6) && defined(IPV6_TCLASS)
  #ifndef ENABLE_QOS6
    #define ENABLE_QOS6
  #endif
#endif
#if defined(ENABLE_QOS4) || defined(ENABLE_QOS6)
  #ifndef ENABLE_QOS
    #define ENABLE_QOS
  #endif
#endif

typedef union inaddr_union {
  struct in_addr in;
  uint8_t s_addr8[4];
#ifdef ENABLE_IPV6
  struct in6_addr in6;
#endif
} t_ipaddr;

// stat fields description
typedef struct s_stat {
  uint len, min;
  const char *name, *hint, key;
} t_stat;

// cmd help messages
typedef enum {CH_NA = 0, CH_INT, CH_STR} t_ch_type;
typedef struct s_cmd_hint {
  const char *key, *hint;
  t_ch_type type;
} t_cmd_hint;

enum {
  NAMELEN   = 256,
  MAXFLD    =  20, // fields in custom set to display stats
  MAXLABELS =   8, // mpls labels
};

typedef enum {
  DisplayAuto, // curses mode if available, otherwise split mode
  DisplayReport,
  DisplayTUI,
#ifdef OUTPUT_FORMAT_TXT
  DisplayTXT,
#endif
#ifdef OUTPUT_FORMAT_CSV
  DisplayCSV,
#endif
#ifdef OUTPUT_FORMAT_JSON
  DisplayJSON,
#endif
#ifdef OUTPUT_FORMAT_TOON
  DisplayTOON,
#endif
#ifdef OUTPUT_FORMAT_XML
  DisplayXML,
#endif
} display_mode_t;

typedef enum {
  ActionNone = 0, ActionQuit, ActionReset, ActionPauseResume,
  ActionProto, ActionUDP,
#ifdef USE_RAW
  ActionTCP,
#endif
  ActionCache, ActionJttr,
#ifdef WITH_MPLS
  ActionMPLS,
#endif
#ifdef ENABLE_DNS
  ActionDNS,
#endif
#ifdef WITH_IPINFO
  ActionASN, ActionII, ActionMultiII,
#endif
#ifdef WITH_MENU
  ActionMenuCyclesUnlim,
  ActionMenuNoCache,
#endif
  MaxActions
} key_action_t;

// misc
#define NOOP ((void)0)

#define MIL   1000
#define MICRO 1000000
#define NANO  1000000000
#define UNKN_ITEM "???"
#define AT_FMT "%2d."
#define SETTLED_ELEMS "LDRS" // Lost-Drop-Recv-Sent

#define CTRL_C    3
#define C_ESCAPE 27
#define C_SPACE ' '

#define REPORT_PINGS 100 // default run-cycles
#define CACHE_TIMEOUT 60 // default if enabled, in seconds

// options
typedef struct opts_s {
  bool
    interactive,
    //
    both,     // -b
    mpls,     // -e
    endpoint, // -fa
    jitter,   // -j
#ifdef WITH_IPINFO
    asn,      // -l
    ipinfo,   // -L
#endif
#ifdef WITH_MOUSE
    mouse,    // -M (disable)
#endif
#ifdef ENABLE_DNS
    dns,      // -n
#endif
    pause,    // runtime pause/resume states
    stat,     // -S
    tcp,      // -t
    udp,      // -u
#ifdef WITH_IPINFO
    multi,    // -y
#endif
    bell,     // -d 7th bit (beep at target)
    visible,  // -d 6th bit (visible bell: flash)
    audible,  // -d 5th bit (beep)
    color;    // -d 4th bit (color mode)
  uint8_t
    chart;    // -d 1st and 2nd bits
  int
    pattern,  // -b payload_pattern
    cycles,   // -c cycles_to_run
    minttl,   // -f first_ttl
    maxttl,   // -m max_ttl
    interval, // -i interval
#ifdef ENABLE_QOS
    qos,      // -q qos
#endif
    size,     // -s packet_size
    syn,      // -T tcp_timeout
    cache,    // -x
    port;     // port from 'target:port' in tcp/udp modes
} opts_t;

// options' cksum
typedef union opt_sum_u {
  uint un;
  struct { uint
    interactive :1,
    //
    both     :1, // -b
    mpls     :1, // -e
    endpoint :1, // -fa
    jitter   :1, // -j
#ifdef WITH_IPINFO
    asn      :1, // -l
    ipinfo   :1, // -L
#endif
#ifdef ENABLE_DNS
    dns      :1, // -n
#endif
    pause    :1, // -p
    stat     :1, // -S
    tcp      :1, // -t
    udp      :1, // -u
    cache    :1, // -x
#ifdef WITH_IPINFO
    multi    :1, // -y (multi ipinfo sources)
#endif
    //
    bell     :1, // -d 7th bit (beep at target)
    visible  :1, // -d 6th bit (visible bell: flash)
    audible  :1, // -d 5th bit (beep)
    color    :1, // -d 4th bit (color mode)
    chart    :1, // -d 1st and 2nd bits
    //
    minttl   :1, // -f first_ttl
    maxttl   :1, // -m max_ttl
#ifdef ENABLE_QOS
    qos      :1, // -q qos
#endif
    //
    pattern  :1, // -b payload_pattern
    cycles   :1, // -c cycles_to_run
    interval :1, // -i interval
    size     :1, // -s packet_size
    syn      :1, // -T tcp_timeout
    port     :1; // port from 'target:port' in tcp/udp modes
  } s;
} opt_sum_t;

#define OPT_SUM(tag) do {opt_sum.s.tag = (run_opts.tag != ini_opts.tag);} while(0)
#define USED_PROTO (run_opts.udp ? "UDP" : (run_opts.tcp ? "TCP" : "ICMP"))
#define CHART_MODE (run_opts.chart | (run_opts.color ? (1 << 3) : 0))

// note, VA_OPT min compat: gcc8, clang6
#if (__GNUC__ >= 8) || (__clang_major__ >= 6) || (__STDC_VERSION__ >= 202311L)
#define WARNF(fmt, ...)   warn("%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define WARNXF(fmt, ...) warnx("%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define ERRF(status, fmt, ...)   err(status, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define ERRXF(status, fmt, ...) errx(status, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#define FAILF(fmt, ...)   errx(EXIT_FAILURE, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
#else /* no VA_OPT, use GNU extension */
#define WARNF(fmt, ...)   warn("%s: " fmt, __func__, ##__VA_ARGS__)
#define WARNXF(fmt, ...) warnx("%s: " fmt, __func__, ##__VA_ARGS__)
#define ERRF(status, fmt, ...)   err(status, "%s: " fmt, __func__, ##__VA_ARGS__)
#define ERRXF(status, fmt, ...) errx(status, "%s: " fmt, __func__, ##__VA_ARGS__)
#define FAILF(fmt, ...)   errx(EXIT_FAILURE, "%s: " fmt, __func__, ##__VA_ARGS__)
#endif /* VA_OPT, VA_ARGS */

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

#ifndef ARRAY_LEN
#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))
#endif

// externs
extern const char *mtrname;
extern display_mode_t display_mode;

extern int sum_sock[];     // summary open()/close() calls for sockets

extern uint16_t pid16;     // 16 bits of process ID
#if defined(OUTPUT_FORMAT_TXT) || defined(OUTPUT_FORMAT_CSV) || defined(OUTPUT_FORMAT_JSON) || defined(OUTPUT_FORMAT_TOON) || defined(OUTPUT_FORMAT_XML)
#define OUTPUT_FORMAT
extern uint mtr_optc;
extern const char* mtr_optv[32]; // option list
#endif
extern char mtr_options[]; // options in one line
extern opts_t run_opts;    // runtime options
extern opts_t ini_opts;    // initial options
extern opt_sum_t opt_sum;  // checksum changes

#ifdef TUIMODE
typedef enum {UNKNLOOK = -1, OLDLOOK = 0, NEWLOOK = 1/*, REVLOOK*/} tuilook_t;
extern tuilook_t tuilook;
#endif

extern int istty;
#define ANSI_NORM    "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"
#ifdef USE_COLOR
#define TTY_NORM    (istty ? ANSI_NORM    : "")
#define TTY_BOLD    (istty ? ANSI_BOLD    : "")
#define TTY_RED     (istty ? ANSI_RED     : "")
#define TTY_GREEN   (istty ? ANSI_GREEN   : "")
#define TTY_YELLOW  (istty ? ANSI_YELLOW  : "")
#define TTY_BLUE    (istty ? ANSI_BLUE    : "")
#define TTY_MAGENTA (istty ? ANSI_MAGENTA : "")
#define TTY_CYAN    (istty ? ANSI_CYAN    : "")
#define TTY_WHITE   (istty ? ANSI_WHITE   : "")
#else
#define TTY_NORM    ""
#define TTY_BOLD    ""
#define TTY_RED     ""
#define TTY_GREEN   ""
#define TTY_YELLOW  ""
#define TTY_BLUE    ""
#define TTY_MAGENTA ""
#define TTY_CYAN    ""
#define TTY_WHITE   ""
#endif
#ifdef USE_COLOR
extern bool nocolor;
#endif

#ifdef WITH_UNICODE
extern bool utf_compat;
#endif

// keys: the value in the array is the index number in stats[]
extern const char *fld_active;
extern t_stat stats[];
extern const int stat_max;

extern char srchost[];
extern const char *dsthost;

enum { COMMA = ',', SEMICOLON = ';', VSLASH = '|', PERCENT = '%', UNDERSCORE = '_', QUOTED = '"' };

#endif
