/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball
    Copyright (C) 2005 R.E.Wolff@BitWizard.nl

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef MTR_H
#define MTR_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#include "config.h"
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef ENABLE_IPV6
typedef struct in6_addr ip_t;
#else
typedef struct in_addr ip_t;
#endif

#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define LOG_PRIORITY LOG_NOTICE
#else
#define LOG_PRIORITY LOG_INFO
#endif

#define NAMELEN	256
#define MAXLABELS 8
#define MAXFLD   20  // max fields in custom set to display stats

#define SETBIT(a, n) { a |= 1 << (n);}
#define CLRBIT(a, n) { a &= ~(1 << (n));}
#define TGLBIT(a, n) { a ^= 1 << (n);}
#define CHKBIT(a, n) (((a) >> (n)) & 1)
#define NEQBIT(a, b, n) (((a) ^ (b)) & (1 << (n)))

#define LENVALMIL(val) double _v = (val) / (double)MIL; int _l = val2len(_v);

// stats fields description
struct statf {
  const char key;
  const char *hint;
  const char *name;
  int len;
};

//
extern pid_t mypid;
extern char mtr_args[];
// runtime args' bits
enum RUN_ARG { RA_UDP, RA_TCP, RA_MPLS, RA_ASN, RA_IPINFO, RA_DNS, RA_JITTER, RA_DM0, RA_DM1, RA_CACHE, RA_PAUSE };
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
extern int mtrtype;        // default packet type
#ifdef WITH_MPLS
extern bool enable_mpls;
#endif
extern bool report_wide;
#ifdef ENABLE_DNS
extern bool show_ips;
#endif
extern bool hinit;         // make sure that a hashtable already exists or not
extern int fstTTL;
extern int maxTTL;
extern int remoteport;     // target port
extern int tos;            // type of service set in ping packet
extern bool endpoint_mode; // -fa option
extern bool cache_mode;    // don't ping known hops
extern int cache_timeout;  // cache timeout in seconds
extern int cbitpattern;    // payload bit pattern
extern int cpacketsize;    // default packet size, or user defined
extern int syn_timeout;    // timeout for TCP connections
extern int sum_sock[];     // summary open()/close() calls for sockets
//
#define ERRBYFN_SZ 80
extern int last_neterr;    // last known network error ...
extern char neterr_txt[];  // ... with this text
//
#if defined(CURSESMODE) || defined(SPLITMODE) || defined(GRAPHMODE)
extern int display_offset;
#endif
#if defined(CURSESMODE) || defined(GRAPHMODE)
extern int curses_mode;
extern int curses_mode_max;
extern bool enable_color;
extern bool bell_audible;
extern bool bell_visible;
extern bool bell_target;
#endif
// keys: the value in the array is the index number in statf[]
extern const char *fld_active;
extern const struct statf statf[];
extern const int statf_max;
//
extern char srchost[];
extern const char *dsthost;
extern int display_mode;
extern double wait_time;
extern bool interactive;
extern long max_ping;
//

char *trim(char *s);
int val2len(double v);
#ifdef CURSESMODE
void set_fld_active(const char *s);
bool is_custom_fld(void);
int limit_int(const int v0, const int v1, const int v, const char *it);
#endif
#if defined(CURSESMODE) || defined(GRAPHMODE)
void onoff_jitter(void);
#endif
const struct statf* active_statf(unsigned i);

#endif
