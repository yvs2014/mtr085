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
#include "config.h"

#ifdef ENABLE_IPV6
typedef struct in6_addr ip_t;
#else
typedef struct in_addr ip_t;
#endif

#ifndef HAVE_SOCKLEN_T
//typedef int socklen_t; 
#endif

#define LOG_PRIORITY LOG_INFO

#define NAMELEN	256
#define MAXLABELS 8

#define FLD_ACTIVE_DEFAULT	"LS NABWV"
#define FLD_ACTIVE_JITTER	"DR AGJMXI"

#define SETBIT(n, x)	{ n |= 1 << (x);}
#define CLRBIT(n, x)	{ n &= ~(1 << (x));}
#define TGLBIT(n, x)	{ n ^= 1 << (x);}
#define CHKBIT(n, x)	((n >> (x)) & 1)

// definition stuff used by display such as report, curses...
#define AVLFLD 20		// max available stat-fields to display
#define MAXFLD (2 * AVLFLD)	// max stat-fields to display
typedef unsigned char FLD_BUF_T[MAXFLD + 1];

// dynamic field drawing
struct fields {
  const unsigned char key;
  const char *descr;
  const char *title;
  const char *format;
  int length;
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
// keys: the value in the array is the index number in data_fields[]
extern int fld_index[];
extern char fld_avail[];
extern FLD_BUF_T fld_active;
extern FLD_BUF_T fld_save;
extern const struct fields data_fields[];
//
extern char srchost[];
extern char *dsthost;
extern int display_mode;
extern float wait_time;
extern bool interactive;
extern int max_ping;
extern bool alter_ping;
//
// MPLS description
typedef struct { uint32_t lab:20, exp:3, s:1, ttl:8; } mpls_label_t;
typedef struct mpls_data {
  mpls_label_t label[MAXLABELS];
  uint8_t n;
} mpls_data_t;
//

char *trim(char *s);
uint16_t str2dnsid(const char* s);
void set_fld_active(const char *s);
const char *mpls2str(const mpls_label_t *label, int indent);

#endif
