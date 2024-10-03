/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997,1998  Matt Kimball

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

#ifndef NET_H
#define NET_H

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>

#include "common.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#define MAXHOST 64          // if you choose 256, then adjust IDMASK ID2AT AT2ID ID2NDX
#define MAXPATH 8           // if you change it, then adjust macros
#define MAXSEQ 16384        // maximum pings in processing
// 16bits as [hash:7 at:6 ndx:3]
#define IDMASK    (0xFE00)
#define AT2ID(n)  ((n & 0x003F) << 3)
#define ID2AT(n)  ((n >> 3) & 0x003F)
#define ID2NDX(n) (n & 0x7)

#define MAXPACKET 4470		// largest test packet size
#define MINPACKET 28		// 20 bytes IP and 8 bytes ICMP or UDP

#ifdef CURSESMODE
#define SAVED_PINGS 200
#define CT_UNKN   -1
#define CT_UNSENT -2
#define CT_SEAL   -3
#endif

extern int af;

extern bool (*addr_exist)(const void *); // true if not 0
extern bool (*addr_equal)(const void *, const void *);
extern void (*addr_copy)(void *dst, const void *src);

extern unsigned long net_queries[];
extern unsigned long net_replies[];

#ifdef WITH_IPINFO
#define MAX_TXT_ITEMS 25
#endif

#define PAUSE_BETWEEN_QUERIES 3 // pause between identical queries (and ipinfo too), in seconds
#define TXT_PTR_PAUSE 1         // pause between txt and ptr queries, in seconds

// time stats, in msec
typedef struct timemsec {
  time_t ms;  // in milliseconds
  long frac;  // in nanoseconds
} timemsec_t;

// wrapper: __has_attribute
#ifndef __has_attribute
#define __has_attribute(attr)  0
#endif
// attribute: __packed__
#if __has_attribute(__packed__)
#define PACKIT __attribute__((__packed__))
#else
#define PACKIT
#endif

#ifdef WITH_MPLS
typedef union PACKIT mpls_label { // RFC4950
  struct {
#if BYTE_ORDER == LITTLE_ENDIAN
  uint32_t ttl:8;
  uint32_t bos:1;
  uint32_t exp:3;
  uint32_t lab:20;
#elif BYTE_ORDER == BIG_ENDIAN
  uint32_t lab:20;
  uint32_t exp:3;
  uint32_t bos:1;
  uint32_t ttl:8;
#else
#error "Undefined byte order"
#endif
  };
  uint32_t u32;
} mpls_label_t; /* must be 4 bytes */

typedef struct mpls_data {
  mpls_label_t label[MAXLABELS]; // N x 32b labels
  uint8_t n;
} mpls_data_t;
#endif

// Address(es) plus associated data
typedef struct eaddr {
  t_ipaddr ipaddr;
#ifdef WITH_MPLS
  mpls_data_t mpls;
#endif
  char *q_ptr, *r_ptr; // t_ptr query, reply
  time_t q_ptr_ts;     // timestamp when 'q_ptr' is sent
#ifdef WITH_IPINFO
  char *q_txt;                // t_txt query
  char *r_txt[MAX_TXT_ITEMS]; // t_txt parsed reply
  time_t q_txt_ts;            // timestamp when 'q_txt' is sent
#endif
} eaddr_t;

// Hop description
struct nethost {
  // addresses with all associated data (dns names, mpls labels, extended ip info)
  eaddr_t eaddr[MAXPATH];
  int current;            // index of the last received address
  // a lot of statistics
  int sent, recv;         // %d
  timemsec_t last, best, worst;  // >10 ? %d : %1.f [msec]
  double avg, mean;              // >10 ? %d : %1.f [msec]
  double jitter, javg, jworst, jinta; // jitters
  long double var;        // variance as base for std deviance: sqrt(var/(recv-1))
  bool transit, up;       // states: ping in transit, host alive
#ifdef CURSESMODE
  int saved[SAVED_PINGS]; // map for display mode: <0 " ?" chars, >=0 pong in usec
  int saved_seq_offset;
#endif
  time_t seen;            // timestamp for caching, last seen
};
extern struct nethost host[];
typedef struct atndx { int at, ndx, type; } atndx_t;

extern char localaddr[];

// helpful macros
#define CURRENT_IP(at)   (host[at].eaddr[host[at].current].ipaddr)
#define IP_AT_NDX(at, ndx)   (host[at].eaddr[ndx].ipaddr)
#ifdef WITH_MPLS
#define CURRENT_MPLS(at) (host[at].eaddr[host[at].current].mpls)
#define MPLS_AT_NDX(at, ndx) (host[at].eaddr[ndx].mpls)
#endif
#define QPTR_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_ptr)
#define RPTR_AT_NDX(at, ndx) (host[at].eaddr[ndx].r_ptr)
#define QPTR_TS_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_ptr_ts)
#ifdef WITH_IPINFO
#define QTXT_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_txt)
#define RTXT_AT_NDX(at, ndx, num) (host[at].eaddr[ndx].r_txt[num])
#define QTXT_TS_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_txt_ts)
#endif

#define FAIL_POSTPONE(rcode, fmt, ...) { last_neterr = rcode; \
  WARNX_(fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
  snprintf(neterr_txt, ERRBYFN_SZ, fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
  LOG_RE_(false, fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
}

#define FAIL_CLOCK_GETTIME FAIL_POSTPONE(errno, "%s", "clock_gettime()");

enum { IPV6_DISABLED = false, IPV6_ENABLED = true };

void net_settings(
#ifdef ENABLE_IPV6
bool ipv6_enabled
#else
void
#endif
);
bool net_open(void);
void net_assert(void);
void net_set_type(int type);
bool net_set_host(t_ipaddr *ipaddr);
bool net_set_ifaddr(const char *ifaddr);
void net_reset(void);
void net_close(void);
int net_wait(void);
void net_icmp_parse(struct timespec *recv_at);
void net_tcp_parse(int sock, int seq, int noerr, struct timespec *recv_at);
bool net_timedout(int seq);
int net_min(void);
int net_max(void);
const char *net_elem(int at, char c);
int net_send_batch(void);
void net_end_transit(void);
int net_duplicate(int at, int seq);

const char *strlongip(t_ipaddr *ipaddr);
bool addr4exist(const void *a);
bool addr4equal(const void *a, const void *b);
void addr4copy(void *a, const void *b);
#ifdef ENABLE_IPV6
bool addr6exist(const void *a);
bool addr6equal(const void *a, const void *b);
void addr6copy(void *a, const void *b);
void net_setsocket6(void);
#endif
#ifdef WITH_MPLS
const char *mpls2str(const mpls_label_t *label, int indent);
#endif
uint16_t str2hint(const char* s, uint16_t at, uint16_t ndx);
void waitspec(struct timespec *tv);

#endif
