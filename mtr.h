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

#ifdef ENABLE_IPV6
typedef struct in6_addr ip_t;
#else
typedef struct in_addr ip_t;
#endif

#define LOG_PRIORITY LOG_INFO

#define NAMELEN	256
#define MAXLABELS 8
#define MAXFLD   20  // max fields in custom set to display stats

#define SETBIT(n, x) { n |= 1 << (x);}
#define CLRBIT(n, x) { n &= ~(1 << (x));}
#define TGLBIT(n, x) { n ^= 1 << (x);}
#define CHKBIT(n, x) ((n >> (x)) & 1)

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
extern unsigned iargs;     // args passed interactively (used to display hints)
  // bits:
  //   0 [u]: UDP mode
  //   1 [t]: TCP mode
  //   2 [e]: MPLS on/off
  //   3 [z]: ASN lookup
  //   4 [y]: IP Info (ASN, etc)
  //   5 [n]: DNS on/off
  //   6 [j]: latency / jitter
  //   7 [d]: display types (4 modes: 2bits)
  //   8 [d]: -//-
  //   9 [x]: cache mode
extern int mtrtype;        // default packet type
extern bool enable_mpls;
extern bool report_wide;
extern bool show_ips;
extern bool hinit;         // make sure that a hashtable already exists or not
extern int fstTTL;
extern int maxTTL;
extern int bitpattern;     // packet bit pattern used by ping
extern int remoteport;     // target port
extern int tos;            // type of service set in ping packet
extern bool endpoint_mode; // -fa option
extern bool cache_mode;    // don't ping known hops
extern int cache_timeout;  // cache timeout in seconds
extern int cpacketsize;    // default packet size, or user-defined
extern int tcp_timeout;    // timeout for TCP connections
extern int sum_sock[];     // opened-closed sockets
//
extern int display_offset;
#if defined(CURSES) || defined(GRAPHCAIRO)
extern int curses_mode;
extern int curses_mode_max;
extern int color_mode;
extern int audible_bell;
extern int visible_bell;
extern int target_bell_only;
#endif
// keys: the value in the array is the index number in statf[]
extern const char *fld_active;
extern const struct statf statf[];
extern const int statf_max;
//
extern char srchost[];
extern char *dsthost;
extern int display_mode;
extern double wait_time;
extern bool interactive;
extern long max_ping;
extern bool alter_ping;
//

char *trim(char *s);
int val2len(double v);
void set_fld_active(const char *s);
bool is_custom_fld(void);
void onoff_jitter(void);
const struct statf* active_statf(unsigned i);
int limit_int(const int v0, const int v1, const int v, const char *it);

#endif
