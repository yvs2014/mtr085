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
#include <netdb.h>

#include "config.h"
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN	46
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

#ifdef CURSES
#define SAVED_PINGS 200
#define CT_UNKN   -1
#define CT_UNSENT -2
#define CT_SEAL   -3
#endif

extern int af;
extern ip_t unspec_addr;

extern bool (*addr_exist)(const void *); // true if specified
extern bool (*addr_equal)(const void *, const void *); // equal
extern void* (*addr_copy)(void *a, const void *b);

extern unsigned long net_queries[];
extern unsigned long net_replies[];

#ifdef IPINFO
#define MAX_TXT_ITEMS 25
#endif

#define PAUSE_BETWEEN_QUERIES 10 // pause between dns queries, in seconds

// time stats, in msec
typedef struct timemsec {
  time_t ms; // in milliseconds
  int frac;  // in nanoseconds
} timemsec_t;

typedef union mpls_label { // RFC4950
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

// Address(es) plus associated data
typedef struct eaddr {
  ip_t ip;
  mpls_data_t mpls;
  char *q_ptr, *r_ptr; // t_ptr query, reply
  time_t q_ptr_ts;     // timestamp when 'q_ptr' is sent
#ifdef IPINFO
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
#ifdef CURSES
  int saved[SAVED_PINGS]; // map for display mode: <0 " ?" chars, >=0 pong in usec
  int saved_seq_offset;
#endif
  time_t seen;            // timestamp for caching, last seen
};
extern struct nethost host[];

// helpful macros
#define CURRENT_IP(at)   (host[at].eaddr[host[at].current].ip)
#define CURRENT_MPLS(at) (host[at].eaddr[host[at].current].mpls)
#define IP_AT_NDX(at, ndx)   (host[at].eaddr[ndx].ip)
#define MPLS_AT_NDX(at, ndx) (host[at].eaddr[ndx].mpls)
#define QPTR_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_ptr)
#define RPTR_AT_NDX(at, ndx) (host[at].eaddr[ndx].r_ptr)
#define QPTR_TS_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_ptr_ts)
#ifdef IPINFO
#define QTXT_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_txt)
#define RTXT_AT_NDX(at, ndx, num) (host[at].eaddr[ndx].r_txt[num])
#define QTXT_TS_AT_NDX(at, ndx) (host[at].eaddr[ndx].q_txt_ts)
#endif

extern char localaddr[];

void net_init(int ipv6);
bool net_open(void);
bool net_set_host(struct hostent *h);
bool net_set_ifaddr(char *ifaddr);
void net_reset(void);
void net_close(void);
int net_wait(void);
void net_icmp_parse(void);
void net_tcp_parse(int sock, int seq, int noerr);
bool net_timedout(int seq);
int net_min(void);
int net_max(void);
const char *net_elem(int at, char c);
int net_send_batch(void);
void net_end_transit(void);
int net_duplicate(int at, int seq);

void sockaddrtop(struct sockaddr *saddr, char *strptr, size_t len);
const char *strlongip(ip_t *ip);
bool addr4equal(const void *a, const void *b);
void* addr4copy(void *a, const void *b);
#ifdef ENABLE_IPV6
bool addr6equal(const void *a, const void *b);
void* addr6copy(void *a, const void *b);
void net_setsocket6(void);
#endif
const char *mpls2str(const mpls_label_t *label, int indent);
uint16_t str2hint(const char* s, uint16_t at, uint16_t ndx);
void waitspec(struct timespec *tv);

#endif
