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

/*
    Non-blocking DNS portion --
    Copyright (C) 1998 by Simon Kirby <sim@neato.org>
    Released under GPL, as above.
*/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <search.h>
#include <arpa/nameser.h>

#include "config.h"
#include "mtr.h"
#include "dns.h"
#include "net.h"

#ifdef ENABLE_IPV6
#ifdef __GLIBC__
#define NSSOCKADDR6(i) (myres._u._ext.nsaddrs[i])
#elif defined(__OpenBSD__)
#define NSSOCKADDR6(i) ((struct sockaddr_in6 *) &(_res_ext.nsaddr_list[i]))
#else
#define NSSOCKADDR6(i) (&(myres._u._ext.ext->nsaddrs[i].sin6))
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__)
struct __res_state_ext {
  union res_sockaddr_union nsaddrs[MAXNS];
  struct sort_list {
    int af;
    union {
      struct in_addr ina;
      struct in6_addr in6a;
    } addr, mask;
  } sort_list[MAXRESOLVSORT];
  char nsuffix[64];
  char nsuffix2[64];
#ifdef __FreeBSD__
  struct timespec conf_mtim;
  time_t conf_stat;
  u_short reload_period;
#endif
};
#endif
#endif

#ifdef __OpenBSD__
#define MYRES_INIT(res) res_init()
#define MYRES_CLOSE(res)
#define MYRES_QUERY(res, ...) res_mkquery(__VA_ARGS__)
#else
#define MYRES_INIT(res) res_ninit(&res)
#define MYRES_CLOSE(res) res_nclose(&res)
#define MYRES_QUERY(res, ...) res_nmkquery(&res, __VA_ARGS__)
#endif

#ifdef LOG_DNS
#include <syslog.h>
#define DNSLOG_MSG(format, ...) { syslog(LOG_PRIORITY, format, __VA_ARGS__); }
#define DNSLOG_RET(format, ...) { syslog(LOG_PRIORITY, format, __VA_ARGS__); return; }
#else
#define DNSLOG_MSG(format, ...)  {}
#define DNSLOG_RET(format, ...)  { return; }
#endif

struct atndx { int at, ndx; };

// global
bool enable_dns = true;	// use DNS by default
#ifndef __OpenBSD__
struct __res_state myres;
#endif
//

static bool dns_initiated = false;
static int resfd = -1;
#ifdef ENABLE_IPV6
static int resfd6 = -1;
#endif

#ifdef ENABLE_IPV6
static struct sockaddr_storage from_sastruct;
static struct sockaddr_in6 * from6 = (struct sockaddr_in6 *) &from_sastruct;
#else
static struct sockaddr_in from_sastruct;
#endif
static struct sockaddr_in * from4 = (struct sockaddr_in *) &from_sastruct;
static struct sockaddr * from = (struct sockaddr *) &from_sastruct;

int dns_waitfd(int family) {
 return (enable_dns && dns_initiated) ? (
#ifdef ENABLE_IPV6
  (family == AF_INET6) ? resfd6 :
#endif
  resfd) : -1;
}

inline int dns_query(int op, const char *dname, int class, int type, const unsigned char *data, int datalen,
  const unsigned char *newrr, unsigned char *buf, int buflen) {
  return MYRES_QUERY(myres, op, dname, class, type, data, datalen, newrr, buf, buflen);
}

bool dns_init(void) {
  if (dns_initiated)
    return true;
  if (MYRES_INIT(myres) < 0) {
    perror("dns_init()");
    return false;
  }
  if (!myres.nscount) {
    perror("dns_init(): no defined nameservers");
    return false;
  }
  myres.options |= RES_DEFAULT;
  myres.options &= ~(RES_DNSRCH | RES_DEFNAMES);
  dns_initiated = true;
  return true;
}

void dns_socket(void) {
  int option = 1;
  if ((resfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    perror("dns_socket(): socket()");
  else
    if (setsockopt(resfd, SOL_SOCKET, SO_BROADCAST, (char *)&option, sizeof(option)) < 0)
      perror("dns_socket(): setsockopt()");
#ifdef ENABLE_IPV6
  if ((resfd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
//    perror("dns_open(): socket6()");
  {}
  else
    if (setsockopt(resfd6, SOL_SOCKET, SO_BROADCAST, (char *)&option, sizeof(option)) < 0)
      perror("dns_socket(): setsockopt6()");
#endif
  if ((resfd < 0)
#ifdef ENABLE_IPV6
   || (resfd6 < 0)
#endif
     )
    fprintf(stderr, "dns_socket() failed\n");
}

void dns_open(void) {
  if (!enable_dns)
    return;
  DNSLOG_MSG("%s", "dns open");
  if (!dns_initiated)
    dns_init();
  dns_socket();
}

void dns_close(void) {
  // anyway clear allocated memory for query/response cache
  for (int at = 0; at < MAXHOST; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      set_new_addr(at, ndx, &unspec_addr, NULL);
  // res_nclose()
  if (dns_initiated) {
    MYRES_CLOSE(myres);
    dns_initiated = false;
  }
  // close sockets
  if (resfd >= 0)
    close(resfd);
#ifdef ENABLE_IPV6
  if (resfd6 >= 0)
    close(resfd6);
#endif
}

#ifdef ENABLE_IPV6
/* Returns an ip6.arpa character string. */
static void addr2ip6arpa(ip_t *ip, char *buf) {
  unsigned char *p = (unsigned char *)ip;
  char *b = buf;
  for (int i = sizeof(struct in6_addr) - 1; i >= 0; i--, b += 4)
    sprintf(b, "%x.%x.", p[i] % 16, p[i] >> 4);
  sprintf(b, "ip6.arpa");
  return;
}
#endif

char* lookup_query(ip_t *ip) {
  static char lookup_query_buf[MAXDNAME];
#ifdef ENABLE_IPV6
  if (af == AF_INET6)
    addr2ip6arpa(ip, lookup_query_buf);
  else /* if (af == AF_INET) */
#endif
    snprintf(lookup_query_buf, sizeof(lookup_query_buf), "%u.%u.%u.%u.in-addr.arpa",
      ((uint8_t*)ip)[3], ((uint8_t*)ip)[2], ((uint8_t*)ip)[1], ((uint8_t*)ip)[0]);
  return lookup_query_buf;
}

static void sendrequest(int at, int ndx) {
  unsigned char buf[PACKETSZ];
  const char *qstr = Q_AT_NDX(at, ndx);
  int r = dns_query(QUERY, qstr, C_IN, T_PTR, NULL, 0, NULL, buf, sizeof(buf));
  if (r < 0) {
    const char *e = strerror(errno);
    perror("dns_query()");
    DNSLOG_RET("dns_query(%*s): %s", (int)sizeof(buf), buf, e);
  }

  HEADER *hp = (HEADER*)buf;
  hp->id = str2hint(qstr, at, ndx);
  DNSLOG_MSG("Send[%u, %u] \"%s\" (id=%u)", at, ndx, qstr, hp->id);

  int re = 0;
  for (int i = 0; i < myres.nscount; i++) {
    if (myres.nsaddr_list[i].sin_family == AF_INET)
      re = sendto(resfd, buf, r, 0, (struct sockaddr *)&myres.nsaddr_list[i], sizeof(struct sockaddr));
#ifdef ENABLE_IPV6
    else if (myres.nsaddr_list[i].sin_family == AF_INET6)
      re = sendto(resfd6, buf, r, 0, (struct sockaddr *)NSSOCKADDR6(i), sizeof(struct sockaddr_in6));
#endif
    if (re < 0) {
      const char *e = strerror(errno);
#ifdef LOG_DNS
      DNSLOG_MSG("sendto#%d failed: %s", i, e);
#endif
    } else
      break; // one successful request is enough
  }
}

const char *dns_lookup(int at, int ndx) {
  if (!enable_dns) // check if it needs
    return NULL;
  if (R_AT_NDX(at, ndx)) // already known?
    return R_AT_NDX(at, ndx);
  ip_t *ip = &IP_AT_NDX(at, ndx);
  if (addr_spec(ip)) { // on the off chance
    if (!Q_AT_NDX(at, ndx)) { // set dns query string if not set yet
      Q_AT_NDX(at, ndx) = strndup(lookup_query(ip), MAXDNAME);
      if (!Q_AT_NDX(at, ndx)) {
        perror("dns_lookup(): strndup()");
        return NULL;
      }
    }
    sendrequest(at, ndx);
  }
  return NULL;
}

struct atndx *chk_qatn(const char* q, int at, int ndx) {
  if (Q_AT_NDX(at, ndx))
    if (!strncasecmp(Q_AT_NDX(at, ndx), q, MAXDNAME)) {
      static struct atndx qatn;
      qatn.at = at;
      qatn.ndx = ndx;
      return &qatn;
    }
  return NULL;
}

struct atndx *find_query(const char* q, uint16_t hint) {
  struct atndx *re = chk_qatn(q, ID2AT(hint), ID2NDX(hint)); // correspond to [hash:7 at:6 ndx:3]
  if (re)
    return re;     // found by hint
  int max = net_max();
  for (int at = net_min(); at < max; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++) {
      re = chk_qatn(q, at, ndx);
      if (re)
        return re; // found
    }
  return NULL;     // not found
}

struct atndx *expand_query(const u_char *packet, int psize, const u_char *dn, char *answer, int asize, uint16_t id, int *r) {
  *r = dn_expand(packet, packet + psize, dn, answer, asize);
  if (*r < 0) {
    DNSLOG_MSG("%s", "dn_expand() failed while expanding query domain");
    return NULL;
  }
  struct atndx *an = find_query(answer, id); // id as a hint
  if (!an)
    DNSLOG_MSG("Unknown response with id=%u q=%s", id, answer);
  return an;
}

void save_answer(int at, int ndx, const char* answer) {
  if (R_AT_NDX(at, ndx)) {
    DNSLOG_MSG("Duplicate or update at=%d ndx=%d for %s", at, ndx, strlongip(&IP_AT_NDX(at, ndx)));
    free(R_AT_NDX(at, ndx));
    R_AT_NDX(at, ndx) = NULL;
  }
  R_AT_NDX(at, ndx) = strndup(answer, MAXDNAME);
  if (!R_AT_NDX(at, ndx))
    fprintf(stderr, "save_answer(at=%d, ndx=%d): strndup(): %s\n", at, ndx, strerror(errno));
}

static void parserespacket(unsigned char *buf, int l) {
  static char answer[MAXDNAME];

  if (l < (int) sizeof(HEADER))
    DNSLOG_RET("%s", "Packet smaller than standard header size");
  if (l == (int) sizeof(HEADER))
    DNSLOG_RET("%s", "Packet has empty body");
  HEADER *hp = (HEADER*)buf;

  DNSLOG_MSG("Got %d bytes, id=%u [at=%u ndx=%u]", l, hp->id, ID2AT(hp->id), ID2NDX(hp->id));

  hp->qdcount = ntohs(hp->qdcount);
  hp->ancount = ntohs(hp->ancount);
  hp->nscount = ntohs(hp->nscount);
  hp->arcount = ntohs(hp->arcount);
  DNSLOG_MSG("Received nameserver reply (qd:%u an:%u ns:%u ar:%u)", hp->qdcount, hp->ancount, hp->nscount, hp->arcount);
  if (hp->tc)     // truncated packet
    DNSLOG_RET("%s", "Nameserver packet truncated");
  if (!hp->qr)    // not a reply
    DNSLOG_RET("%s", "Query packet received on nameserver communication socket");
  if (hp->opcode) // non-standard query
    DNSLOG_RET("%s", "Invalid opcode in response packet");
  unsigned char *eob = buf + l;
  unsigned char *c = buf + sizeof(HEADER);
  int r;
  struct atndx *an;

  if (hp->rcode != NOERROR) {
    if (hp->rcode == NXDOMAIN) {
      DNSLOG_MSG("%s", "No such name")
      if ((an = expand_query(buf, l, c, answer, sizeof(answer) - 1, hp->id, &r))) {
        // save as it is, i.e. in dotted-decimal notation
        strncpy(answer, strlongip(&IP_AT_NDX(an->at, an->ndx)), sizeof(answer) - 1);
        save_answer(an->at, an->ndx, answer);
      }
    } else
      DNSLOG_RET("Received error response %u", hp->rcode);
    return;
  }

  if (!(hp->ancount))
    DNSLOG_RET("%s", "No error returned but no answers given");
  if (hp->qdcount != 1)
    DNSLOG_RET("%s", "Reply does not contain one query");
  if (c > eob)
    DNSLOG_RET("%s", "Reply too short");

  memset(answer, 0, sizeof(answer));
  if (!expand_query(buf, l, c, answer, sizeof(answer) - 1, hp->id, &r))
    return;
  DNSLOG_MSG("Response for %s", answer);

  c += r;
  if (c + 4 > eob)
    DNSLOG_RET("%s", "Query resource record truncated");
  { int type; GETSHORT(type, c); if (type != T_PTR) DNSLOG_RET("Not PTR query type %u", type); }
  c += INT16SZ;	// skip class

  for (int i = hp->ancount + hp->nscount + hp->arcount; i; i--) {
    if (c > eob)
      DNSLOG_RET("%s", "Packet does not contain all specified resouce records");
    memset(answer, 0, sizeof(answer));
    an = expand_query(buf, l, c, answer, sizeof(answer) - 1, hp->id, &r);
    c += r;
    if (c + 10 > eob)
      DNSLOG_RET("%s", "Resource record truncated");
    int type;
    GETSHORT(type, c);
    c += INT16SZ;	// skip class
    c += INT32SZ;	// skip ttl
    int size;
    GETSHORT(size, c);
    if (!size)
      DNSLOG_RET("%s", "Zero size rdata");
    if (c + size > eob)
      DNSLOG_RET("%s", "Specified rdata length exceeds packet size");

    if (an && (type == T_PTR)) { // answer to us
      memset(answer, 0, sizeof(answer));
      r = dn_expand(buf, buf + l, c, answer, sizeof(answer) - 1);
      if (r < 0)
        DNSLOG_RET("%s", "dn_expand() failed while expanding domain in rdata");
      int l = strnlen(answer, sizeof(answer));
      DNSLOG_MSG("Answer[%d]: \"%s\"[%d]", r, answer, l);
      save_answer(an->at, an->ndx, answer);
      return; // let's take first answer
    }
    c += size;
  }
}


void dns_ack(int fd, int family) {
  static struct in_addr localhost4 = { INADDR_LOOPBACK };
#ifdef ENABLE_IPV6
  static struct in6_addr localhost6 = IN6ADDR_LOOPBACK_INIT;
#endif
  static socklen_t fromlen = sizeof(from_sastruct);
  static unsigned char buf[PACKETSZ];

  int r = recvfrom(fd, buf, sizeof(buf), 0, from, &fromlen);
  if (r <= 0) {
    perror("dns_ack(): recvfrom()");
    return;
  }

  /* Check to see if this server is actually one we sent to */
  int i;
#ifdef ENABLE_IPV6
  if (family == AF_INET6) {
    int lh = addr6cmp(&(from6->sin6_addr), &localhost6);
    for (i = 0; i < myres.nscount; i++) {
      if (!addr6cmp(&(NSSOCKADDR6(i)->sin6_addr), &(from6->sin6_addr)))
        break;
      if (!lh)
        if (!addr6cmp(&(NSSOCKADDR6(i)->sin6_addr), &unspec_addr))
          break;
    }
  } else /* if (family == AF_INET) */
#endif
  {
    int lh = addr4cmp(&(from4->sin_addr), &localhost4);
    for (i = 0; i < myres.nscount; i++) {
      if (!addr4cmp(&(myres.nsaddr_list[i].sin_addr), &(from4->sin_addr)))
        break;
      if (!lh)
        if (!addr4cmp(&(myres.nsaddr_list[i].sin_addr), &unspec_addr))
          break;
    }
  }

  if (i != myres.nscount)
    parserespacket(buf, r);
#ifdef LOG_DNS
  else
    DNSLOG_MSG("%s", "Received reply from unknown source");
#endif
}

