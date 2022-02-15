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
#include "config.h"

/* Typedefs */

/*  Find the proper type for 8 bits  */
#if SIZEOF_UNSIGNED_CHAR == 1
typedef unsigned char uint8;
#else
#error No 8 bit type
#endif

/*  Find the proper type for 16 bits  */
#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short uint16;
#elif SIZEOF_UNSIGNED_INT == 2
typedef unsigned int uint16;
#elif SIZEOF_UNSIGNED_LONG == 2
typedef unsigned long uint16;
#else
#error No 16 bit type
#endif

/*  Find the proper type for 32 bits  */
#if SIZEOF_UNSIGNED_SHORT == 4
typedef unsigned short uint32;
#elif SIZEOF_UNSIGNED_INT == 4
typedef unsigned int uint32;
#elif SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long uint32;
#else
#error No 32 bit type
#endif

typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned long dword;

#ifdef ENABLE_IPV6
typedef struct in6_addr ip_t;
#else
typedef struct in_addr ip_t;
#endif

#ifdef __GNUC__
#define UNUSED __attribute__((__unused__))
#else
#define UNUSED
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t; 
#endif

#define NAMELEN	256

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
extern unsigned iargs;	// args passed interactively
extern int mtrtype;	// default packet type
extern bool enable_mpls;
extern bool report_wide;
extern bool show_ips;
extern bool hinit;	// make sure that a hashtable already exists or not
extern int fstTTL;
extern int maxTTL;
extern int bitpattern;	// packet bit pattern used by ping
extern int remoteport;	// target port
extern int tos;		// type of service set in ping packet
extern bool endpoint_mode;	// -fz option
extern int cpacketsize;	// default packet size, or user-defined
extern int tcp_timeout;	// timeout for TCP connections
//
extern int display_offset;
#if defined(CURSES) || defined(GRAPHCAIRO)
extern int curses_mode;
extern int curses_mode_max;
extern int color_mode;
#endif
// keys: the value in the array is the index number in data_fields[]
extern int fld_index[];
extern char fld_avail[];
extern FLD_BUF_T fld_active;
extern FLD_BUF_T fld_save;
//
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

char *trim(char *s);
word str2hash(const char* s);
void set_fld_active(const char *s);
void limit_it(const int v0, const int v1, int *v);

#endif
