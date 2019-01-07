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

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN	46
#endif

int net_preopen(void);
int net_selectsocket(void);
int net_open(struct hostent *host);
void net_reopen(struct hostent *address);
int net_set_interfaceaddress (char *InterfaceAddress);
void net_reset(void);
void net_close(void);
int net_waitfd(void);
void net_process_return(void);

int net_max(void);
int net_min(void);
int net_elem(int at, char c);
int net_send_batch(void);
void net_end_transit(void);
int calc_deltatime (float WaitTime);

#define SAVED_PINGS 200
int net_duplicate(int at, int seq);
int net_process_tcp_fds(void);
int net_tcp_init(void);

void sockaddrtop( struct sockaddr * saddr, char * strptr, size_t len );

int af;
ip_t unspec_addr;	// zero by definition
int (*unaddrcmp)(const void *);
int (*addrcmp)(const void *a, const void *b);
int addr4cmp(const void *a, const void *b);
int addr6cmp(const void *a, const void *b);
void* (*addrcpy)(void *a, const void *b);
void* addr4cpy(void *a, const void *b);
void* addr6cpy(void *a, const void *b);
void net_init(int ipv6_mode);
const char *strlongip(ip_t *ip);

#define MAXPATH 8
#define MaxHost 256

#define MAXPACKET 4470		/* largest test packet size */
#define MINPACKET 28		/* 20 bytes IP header and 8 bytes ICMP or UDP */
#define MAXLABELS 8		/* http://kb.juniper.net/KB2190 (+ 3 just in case) */

/* stuff used by display such as report, curses... */
#define MAXFLD 20		/* max stats fields to display */

/* XXX This doesn't really belong in this header file, but as the
   right c-files include it, it will have to do for now. */

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
  ip_t addrs[MAXPATH];	/* for multi paths byMin */
  int xmit;
  int returned;
  int sent;
  int up;
  long long var;/* variance, could be overflowed */
  int last;
  int best;
  int worst;
  int avg;	/* average:  addByMin */
  int gmean;	/* geometirc mean: addByMin */
  int jitter;	/* current jitter, defined as t1-t0 addByMin */
  int javg;	/* avg jitter */
  int jworst;	/* max jitter */
  int jinta;	/* estimated variance,? rfc1889's "Interarrival Jitter" */
  int transit;
  int saved[SAVED_PINGS];
  int saved_seq_offset;
  struct mplslen mpls;
  struct mplslen mplss[MAXPATH];
};
extern struct nethost host[];

/* dynamic field drawing */
struct fields {
  const unsigned char key;
  const char *descr;
  const char *title;
  const char *format;
  int length;
};
extern struct fields data_fields[];

/* keys: the value in the array is the index number in data_fields[] */
extern int fld_index[];
extern unsigned char fld_active[];
extern unsigned char fld_active_save[];
extern char available_options[];
extern char localaddr[];

void decodempls(int, char *, struct mplslen *, int);

#endif
