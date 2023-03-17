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

/*  Prototypes for functions in net.c  */
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
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

#define MAXPATH 8
#define MAXHOST 256

#define MAXPACKET 4470		/* largest test packet size */
#define MINPACKET 28		/* 20 bytes IP header and 8 bytes ICMP or UDP */
#define MAXLABELS 8		/* http://kb.juniper.net/KB2190 (+ 3 just in case) */

#define SAVED_PINGS 200

extern int af;
extern int packetsize;
extern ip_t unspec_addr;	// zero by definition
extern int (*unaddrcmp)(const void *);
extern int (*addrcmp)(const void *a, const void *b);
extern void* (*addrcpy)(void *a, const void *b);

/* MPLS label object */
struct mplslen {
  unsigned long label[MAXLABELS]; /* label value */
  uint8 exp[MAXLABELS]; /* experimental bits */
  uint8 ttl[MAXLABELS]; /* MPLS TTL */
  char s[MAXLABELS]; /* bottom of stack */
  char labels; /* how many labels did we get? */
};

struct nethost {
  ip_t addr;
  ip_t addrs[MAXPATH]; // for multi paths byMin
  int xmit;
  int returned;
  int sent;
  int up;
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
  struct mplslen mpls;
  struct mplslen mplss[MAXPATH];
  time_t seen;         // timestamp for caching, last seen
};
extern struct nethost host[];

extern char localaddr[];
extern int cycles;     // to see progress on curses screen in cache mode

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
void decodempls(int, char *, struct mplslen *, int);
const char *strlongip(ip_t *ip);
time_t wait_usec(float t);
int addr4cmp(const void *a, const void *b);
int addr6cmp(const void *a, const void *b);
void* addr4cpy(void *a, const void *b);
void* addr6cpy(void *a, const void *b);

#endif
