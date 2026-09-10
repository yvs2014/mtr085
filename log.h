#ifndef LOGATTR_H
#define LOGATTR_H

#ifdef LOGMOD
  #include <syslog.h>
  #if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    #define LOG_PRIORITY LOG_NOTICE
  #else
    #define LOG_PRIORITY LOG_INFO
  #endif
  //
  /* note, VA_OPT min compat: gcc8, clang6 */
  #if (__GNUC__ >= 8) || (__clang_major__ >= 6) || (__STDC_VERSION__ >= 202311L)
    #define LOGMSG(fmt, ...) syslog(LOG_PRIORITY, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__)
    #define LOGRET(fmt, ...) do {                                           \
      syslog(LOG_PRIORITY, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__); \
      return;                                                               \
    } while(0)
    #define LOGRET_RC(rcode, fmt, ...) do {                                 \
      syslog(LOG_PRIORITY, "%s: " fmt, __func__ __VA_OPT__(,) __VA_ARGS__); \
      return (rcode);                                                       \
    } while(0)
  #else /* no VA_OPT, use GNU extension */
    #define LOGMSG(fmt, ...) syslog(LOG_PRIORITY, "%s: " fmt, __func__, ##__VA_ARGS__)
    #define LOGRET(fmt, ...) do {                                \
      syslog(LOG_PRIORITY, "%s: " fmt, __func__, ##__VA_ARGS__); \
      return;                                                    \
    } while(0)
    #define LOGRET_RC(rcode, fmt, ...) do {                      \
      syslog(LOG_PRIORITY, "%s: " fmt, __func__, ##__VA_ARGS__); \
      return (rcode);                                            \
    } while(0)
  #endif /* VA_OPT, VA_ARGS */
#else
  #define LOGMSG(fmt, ...) ((void)0)
  #define LOGRET(fmt, ...) return
  #define LOGRET_RC(rcode, fmt, ...) return (rcode)
#endif /* LOGMOD */

#endif
