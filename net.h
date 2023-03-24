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

// just in case
#define timer2usec(t) ((t)->tv_sec * 1000000 + (t)->tv_usec)
#ifndef timerclear
#define timerclear(t) ((t)->tv_sec = (t)->tv_usec = 0)
#endif
#ifndef timercmp
#define timercmp(a, b, CMP)          \
  (((a)->tv_sec  ==  (b)->tv_sec)  ? \
   ((a)->tv_usec CMP (b)->tv_usec) : \
   ((a)->tv_sec  CMP (b)->tv_sec))
#endif
#ifndef timeradd
#define timeradd(a, b, s) do {                \
  (s)->tv_sec  = (a)->tv_sec  + (b)->tv_sec;  \
  (s)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
  if ((s)->tv_usec >= 1000000) {              \
    ++(s)->tv_sec;                            \
    (s)->tv_usec -= 1000000;                  \
  }                                           \
} while (0)
#endif
#ifndef timersub
#define timersub(a, b, s) do {                \
  (s)->tv_sec  = (a)->tv_sec  - (b)->tv_sec;  \
  (s)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
  if ((s)->tv_usec < 0) {                     \
    --(s)->tv_sec;                            \
    (s)->tv_usec += 1000000;                  \
  }                                           \
} while (0)
#endif
//

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN	46
#endif

#define MAXHOST 64          // if you choose 256, then adjust IDMASK ID2AT AT2ID ID2NDX
#define MAXPATH 8           // if you change it, then adjust macros
// 16bits as [hash:7 at:6 ndx:3]
#define IDMASK    (0xFE00)
#define AT2ID(n)  ((n & 0x003F) << 3)
#define ID2AT(n)  ((n >> 3) & 0x003F)
#define ID2NDX(n) (n & 0x7)

#define MAXPACKET 4470		// largest test packet size
#define MINPACKET 28		// 20 bytes IP and 8 bytes ICMP or UDP

#define SAVED_PINGS 200

extern int af;
extern int packetsize;
extern ip_t unspec_addr;	// zero by definition
extern bool (*addr_spec)(const void *); // true if address is specified
extern bool (*addr_equal)(const void *, const void *); // true if it's the same address
extern int (*unaddrcmp)(const void *);
extern int (*addrcmp)(const void *a, const void *b);
extern void* (*addrcpy)(void *a, const void *b);

// MPLS description
typedef struct { uint32_t lab:20, exp:3, s:1, ttl:8; } mpls_label_t;
typedef struct mpls_data {
  mpls_label_t label[MAXLABELS]; // N x 32b labels
  uint8_t n;
} mpls_data_t;

// Address(es) plus associated data
typedef struct eaddr {
  ip_t ip;
  mpls_data_t mpls;
  char *q, *r; // dns query, reply
  char *info[10]; // TODO: add ipinfo
} eaddr_t;

// Hop description
struct nethost {
  // addresses with all associated data (dns names, mpls labels, extended ip info)
  eaddr_t eaddr[MAXPATH];
  uint8_t current; // index of the last received address
  //
  // a lot of statistics
  int xmit, returned, sent, up;
  long long var;       // variance, could be overflowed
  time_t last;
  int best;
  int worst;
  int avg;             // average, addByMin
  int gmean;           // geometirc mean, addByMin
  time_t jitter;       // current jitter, defined as t1-t0, addByMin
  int javg;            // avg jitter
  int jworst;          // max jitter
  int jinta;           // estimated variance,? rfc1889's "Interarrival Jitter"
  int transit;
  int saved[SAVED_PINGS];
  int saved_seq_offset;
  time_t seen;         // timestamp for caching, last seen
};
extern struct nethost host[];

// helpful macros
#define CURRENT_IP(at)   (host[at].eaddr[host[at].current].ip)
#define CURRENT_MPLS(at) (host[at].eaddr[host[at].current].mpls)
#define IP_AT_NDX(at, ndx) (host[at].eaddr[ndx].ip)
#define MPLS_AT_NDX(at, ndx) (host[at].eaddr[ndx].mpls)
#define Q_AT_NDX(at, ndx) (host[at].eaddr[ndx].q)
#define R_AT_NDX(at, ndx) (host[at].eaddr[ndx].r)

extern char localaddr[];

void net_init(int ipv6_mode);
int net_tcp_init(void);
int net_preopen(void);
int net_open(struct hostent *host);
int net_selectsocket(void);
int net_set_interfaceaddress(char *InterfaceAddress);
void net_reset(void);
void net_close(void);
int net_waitfd(void);
void net_process_return(void);
int net_max(void);
int net_min(void);
int net_elem(int at, char c);
int net_send_batch(void);
void net_end_transit(void);
int net_duplicate(int at, int seq);
bool net_process_tcp_fds(void);

void sockaddrtop(struct sockaddr *saddr, char *strptr, size_t len);
void decodempls(int num, const uint8_t *packet, mpls_data_t *mpls, int off);
const char *strlongip(ip_t *ip);
time_t wait_usec(float t);
int addr4cmp(const void *a, const void *b);
int addr6cmp(const void *a, const void *b);
void* addr4cpy(void *a, const void *b);
void* addr6cpy(void *a, const void *b);
void set_new_addr(int at, int ndx, const ip_t *ip, const mpls_data_t *mpls);

const char *mpls2str(const mpls_label_t *label, int indent);

#endif
