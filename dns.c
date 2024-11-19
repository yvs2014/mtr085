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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/socket.h>

#include "config.h"
#if defined(LOG_DNS) && !defined(LOGMOD)
#include <errno.h>
#define LOGMOD
#endif
#if !defined(LOG_DNS) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "common.h"

#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
#ifndef BIND_8_COMPAT
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <resolv.h>

#include "dns.h"
#include "net.h"

#ifndef MAXNS
#define MAXNS 3
#endif
#ifndef PACKETSZ
#define PACKETSZ 512
#endif

#ifdef ENABLE_IPV6
#if defined(__GLIBC__) || defined(__linux__)
#define NSADDRS6(i) (myres._u._ext.nsaddrs[i])
#elif defined(__OpenBSD__)
#define NSADDRS6(i) ((struct sockaddr_in6 *)&_res_ext.nsaddr_list[i])
#else
#define NSADDRS6(i) (&myres._u._ext.ext->nsaddrs[i].sin6)
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__sun) || defined(__HAIKU__) || defined(__APPLE__)
#ifdef __HAIKU__
union res_sockaddr_union {
  struct sockaddr_in sin;
  struct sockaddr_in6 sin6;
  char __space[128];
};
#endif
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
  uint16_t reload_period;
#endif
};
#endif
#endif

static int nscount;
static struct sockaddr_in nsaddrs[MAXNS];
#ifdef ENABLE_IPV6
static int nscount6;
static struct sockaddr_in6 nsaddrs6[MAXNS];
#endif

#ifdef HAVE_RES_NMKQUERY
static struct __res_state myres;
#define MYRES_INIT(res) res_ninit(&(res))
#define MYRES_CLOSE(res) res_nclose(&(res))
#define MYRES_QUERY(res, ...) res_nmkquery(&(res), __VA_ARGS__)
#else
extern struct __res_state _res;
#define myres _res
#define MYRES_INIT(res) res_init()
#define MYRES_CLOSE(res)
#define MYRES_QUERY(res, ...) res_mkquery(__VA_ARGS__)
#endif

#define ARPA4_SUFFIX "in-addr.arpa"
#define ARPA6_SUFFIX "ip6.arpa"

// global
bool enable_dns = true;  // use DNS by default
unsigned dns_queries[3]; // number of queries (sum, ptr, txt)
unsigned dns_replies[3]; // number of replies (sum, ptr, txt)
t_sockaddr *custom_res;  // -N option

// external callbacks for T_PTR and T_TXT replies
//   first one is used by net-module
//   and second one - by ipinfo-module
void (*dns_ptr_handler)(int at, int ndx, const char* answer);
void (*dns_txt_handler)(int at, int ndx, const char* answer);
//

static bool dns_ready;
static int resfd = -1;
#ifdef ENABLE_IPV6
static int resfd6 = -1;
#endif

static t_sockaddr sa_from;

int dns_wait(int family) {
 return dns_ready ? (
#ifdef ENABLE_IPV6
  (family == AF_INET6) ? resfd6 :
#endif
  resfd) : -1;
}

static bool dns_sockets(void) {
  if (nscount && (resfd < 0)) {
    resfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (resfd < 0)
      WARN("socket");
    else
      /*summ*/ sum_sock[0]++;
  }
#ifdef ENABLE_IPV6
  if (nscount6 && (resfd6 < 0)) {
    resfd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (resfd6 < 0)
      LOGMSG("socket6");
    else
      /*summ*/ sum_sock[0]++;
  }
#endif
  return (nscount && (resfd >= 0))
#ifdef ENABLE_IPV6
    || (nscount6 && (resfd6 >= 0))
#endif
  ;
}

#define VALIDATE_NS(resaddr) { \
  if ((resaddr) && ((resaddr)->sin_family == AF_INET) && addr4exist(&(resaddr)->sin_addr)) \
    memcpy(&nsaddrs[nscount++], (resaddr), sizeof(nsaddrs[0])); }
#define VALIDATE_NS6(resaddr) { \
  if ((resaddr) && ((resaddr)->sin6_family == AF_INET6) && addr6exist(&(resaddr)->sin6_addr)) \
    memcpy(&nsaddrs6[nscount6++], (resaddr), sizeof(nsaddrs6[0])); }

static inline void dns_nses(void) {
  // note1: res is empty with musl libc, .nscount6 is 0 with glibc
  // note2: res.options are from resolv.conf unless nsserver is defined
  if (custom_res) {
    myres.options = RES_RECURSE;
    if (custom_res->SA_AF == AF_INET)
      memcpy(&nsaddrs[nscount++], custom_res, sizeof(nsaddrs[0]));
#ifdef ENABLE_IPV6
    else if (custom_res->SA_AF == AF_INET6)
      memcpy(&nsaddrs6[nscount6++], custom_res, sizeof(nsaddrs6[0]));
#endif
  } else {
#ifdef ENABLE_IPV6
    for (int i = 0; (i < MAXNS) && (nscount6 < MAXNS); i++)
      VALIDATE_NS6(NSADDRS6(i));
#endif
    for (int i = 0; (i < MAXNS) && (nscount < MAXNS); i++)
      VALIDATE_NS(&myres.nsaddr_list[i]);
  }
  dns_ready =
#ifdef ENABLE_IPV6
    (nscount6 > 0) ||
#endif
    (nscount > 0);
  if (!dns_ready) { WARNX("No nameservers"); MYRES_CLOSE(myres); }
}

#ifdef LOGMOD
static inline void dns_open_finlog(void) {
  LOGMSG("%s", dns_ready ? "ok" : "failed");
  LOGMSG("nscount4=%d", nscount);
  char buff[MAX_ADDRSTRLEN];
  for (int i = 0; i < nscount; i++)
    if (inet_ntop(nsaddrs[i].sin_family, &nsaddrs[i].sin_addr, buff, sizeof(buff)))
      LOGMSG("ns4#%d: %s:%u (af=%u)", i, buff, ntohs(nsaddrs[i].sin_port), nsaddrs[i].sin_family);
    else
      LOGMSG("ns4[%d]: %08x:%u (af=%u)", i, nsaddrs[i].sin_addr.s_addr, ntohs(nsaddrs[i].sin_port), nsaddrs[i].sin_family);
  LOGMSG("nscount6=%d", nscount6);
  for (int i = 0; i < nscount6; i++) {
    if (!inet_ntop(nsaddrs6[i].sin6_family, &nsaddrs6[i].sin6_addr, buff, sizeof(buff)))
      for (size_t j = 0, l = 0; (j < sizeof(nsaddrs6[i].sin6_addr.s6_addr)) && (l < sizeof(buff)); j++) {
        int inc = snprintf(buff + l, sizeof(buff) - l, "%02x", nsaddrs6[i].sin6_addr.s6_addr[j]);
        if (inc > 0) l += inc;
      }
    LOGMSG("ns6#%d: [%s]:%u (af=%u)", i, buff, ntohs(nsaddrs6[i].sin6_port), nsaddrs6[i].sin6_family);
  }
}
#endif

bool dns_open(void) {
  if (dns_ready)
    return true;
  if (MYRES_INIT(myres) < 0)
    WARN("res_init");
  else
    dns_nses();
  if (dns_ready) {
    dns_ready = dns_sockets();
    if (!dns_ready) { MYRES_CLOSE(myres); }
  }
#ifdef LOGMOD
  dns_open_finlog();
#endif
  return dns_ready;
}

void dns_close(void) {
  dns_ready = false;
  if (resfd >= 0) {
    close(resfd);
    /*summ*/ sum_sock[1]++;
    resfd = -1;
  }
#ifdef ENABLE_IPV6
  if (resfd6 >= 0) {
    close(resfd6);
    /*summ*/ sum_sock[1]++;
    resfd6 = -1;
  }
#endif
  if (custom_res) { free(custom_res); custom_res = NULL; }
  MYRES_CLOSE(myres);
  LOGMSG("ok");
}

#ifdef ENABLE_IPV6
#define HEXMASK 0xf
// fill ip6.arpa str
static void ip2arpa6(const uint8_t *ptr, char *buf, int size, const char *suff) {
  int len = 0;
  for (int i = HEXMASK; i >= 0; i--) {
    int inc = snprintf(buf + len, size - len, "%x.%x.", ptr[i] & HEXMASK, ptr[i] >> 4);
    if (inc > 0) len += inc;
    if (len >= size) return;
  }
  snprintf(buf + len, size - len, "%s", suff);
}
#endif

char* ip2arpa(const t_ipaddr *ipaddr, const char *suff4, const char *suff6) {
  static char lqbuf[NAMELEN];
  const uint8_t *p = ipaddr->s_addr8;
#ifdef ENABLE_IPV6
  if (af == AF_INET6) {
    ip2arpa6(p, lqbuf, sizeof(lqbuf), suff6 ? suff6 : ARPA6_SUFFIX);
  } else
#endif
  { snprintf(lqbuf, sizeof(lqbuf), "%d.%d.%d.%d.%s", p[3], p[2], p[1], p[0], suff4 ? suff4 : ARPA4_SUFFIX); }
  return lqbuf;
}

#define SEND2NS(sendto_fd, sendto_addr, sendto_socktype) { \
  int rc = sendto(sendto_fd, req_buf, len, 0, \
    (const struct sockaddr*)(sendto_addr), sizeof(struct sendto_socktype)); \
  /*summ*/ dns_queries[0]++; if (tndx > 0) dns_queries[tndx]++; \
  if (rc >= 0) return rc; \
  LOGMSG("[%d:%d type=%d id=%d] err=%d: %s", at, ndx, type, hp->id, errno, strerror(errno)); \
}
int dns_send_query(int at, int ndx, const char *qstr, int type) {
  static uint8_t req_buf[PACKETSZ];
  if (!dns_ready)
    return -1;
  int len = MYRES_QUERY(myres, QUERY, qstr, C_IN, type, NULL, 0, NULL, req_buf, sizeof(req_buf));
  if (len < 0) {
    WARN("[%d:%d type=%d]", at, ndx, type);
    LOG_RE(-1, "[%d:%d type=%d] failed", at, ndx, type);
  }

  HEADER *hp = (HEADER*)req_buf;
  hp->id = str2hint(qstr, at, ndx);
  LOGMSG("[%d:%d type=%d id=%d]: %s", at, ndx, type, hp->id, qstr);

  { int tndx = (type == T_PTR) ? 1 : ((type == T_TXT) ? 2 : -1);
    for (int i = 0; i < nscount; i++)
      SEND2NS(resfd, &nsaddrs[i], sockaddr_in);
#ifdef ENABLE_IPV6
    for (int i = 0; i < nscount6; i++)
      SEND2NS(resfd6, &nsaddrs6[i], sockaddr_in6);
#endif
  } return -1;
}
#undef SENDTONS

inline const char *dns_ptr_cache(int at, int ndx) {
  return addr_exist(&IP_AT_NDX(at, ndx)) ? RPTR_AT_NDX(at, ndx) : NULL;
}

const char *dns_ptr_lookup(int at, int ndx) {
  if (!enable_dns) // not enabled
    return NULL;
  if (!addr_exist(&IP_AT_NDX(at, ndx))) // on the off chance
    return NULL;
  if (RPTR_AT_NDX(at, ndx)) // already known
    return RPTR_AT_NDX(at, ndx);

  // set query string if not yet (setting a new ip, free this query)
  if (!QPTR_AT_NDX(at, ndx)) {
    QPTR_AT_NDX(at, ndx) = strndup(ip2arpa(&IP_AT_NDX(at, ndx), NULL, NULL), NAMELEN);
    if (!QPTR_AT_NDX(at, ndx)) {
      WARN("[%d:%d]: strndup()", at, ndx);
      return NULL;
  }}

  time_t now = time(NULL);
  if (((now - QPTR_TS_AT_NDX(at, ndx)) >= PAUSE_BETWEEN_QUERIES)
#ifdef WITH_IPINFO
   && ((now - QTXT_TS_AT_NDX(at, ndx)) >= TXT_PTR_PAUSE)
#endif
     ) {
    QPTR_TS_AT_NDX(at, ndx) = now; // save time of trying to send
    dns_send_query(at, ndx, QPTR_AT_NDX(at, ndx), T_PTR);
  }
  return NULL;
}


static atndx_t *get_qatn(const char* q, int at, int ndx) {
  const char *query[] = { QPTR_AT_NDX(at, ndx)
#ifdef WITH_IPINFO
   , QTXT_AT_NDX(at, ndx)
#endif
  };
  for (size_t t = 0; t < sizeof(query) / sizeof(query[0]); t++)
    if (query[t] && !strncasecmp(query[t], q, MAXDNAME)) {
      static atndx_t qatn;
      qatn = (atndx_t){.at = at, .ndx = ndx, .type = t}; // type: 0 - t_ptr, 1 - t_txt
      return &qatn;
    }
  return NULL;
}

static atndx_t *find_query(const char* q, uint16_t hint) {
  atndx_t *re = get_qatn(q, ID2AT(hint), ID2NDX(hint)); // correspond to [hash:7 at:6 ndx:3]
  if (re)
    return re;     // found by hint
  int max = net_max();
  for (int at = net_min(); at < max; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++) {
      re = get_qatn(q, at, ndx);
      if (re)
        return re; // found
    }
  return NULL;     // not found
}

static atndx_t *expand_query(const uint8_t *packet, ssize_t psize, const uint8_t *dn, char *answer, int asize, uint16_t id, int *r) {
  *r = dn_expand(packet, packet + psize, dn, answer, asize);
  if (*r < 0)
    LOG_RE(NULL, "dn_expand() failed while expanding query domain");
  atndx_t *an = find_query(answer, id); // id as a hint
  if (!an)
    LOGMSG("Unknown response with id=%u q=%s", id, answer);
  return an;
}


static void dns_parse_reply(uint8_t *buf, ssize_t len) {
  if (len < (int)sizeof(HEADER))
    LOGRET("Packet smaller than standard header size");
  if (len == (int)sizeof(HEADER))
    LOGRET("Packet has empty body");
  HEADER *hp = (HEADER*)buf;

  LOGMSG("got %zd bytes, id=%u at=%u ndx=%u", len, hp->id, ID2AT(hp->id), ID2NDX(hp->id));
  dns_replies[0]++; /*summ*/

  hp->qdcount = ntohs(hp->qdcount);
  hp->ancount = ntohs(hp->ancount);
  hp->nscount = ntohs(hp->nscount);
  hp->arcount = ntohs(hp->arcount);
//  LOGMSG("qd:%u an:%u ns:%u ar:%u", hp->qdcount, hp->ancount, hp->nscount, hp->arcount);
  if (hp->tc)     // truncated packet
    LOGRET("Truncated packet");
  if (!hp->qr)    // not a reply
    LOGRET("Not a reply");
  if (hp->opcode) // non-standard query
    LOGRET("Invalid opcode");
  uint8_t *eob = buf + len;
  uint8_t *c = buf + sizeof(HEADER);
  int l = 0;
  atndx_t *an = NULL;

  char answer[MAXDNAME] = {0};
  if (hp->rcode != NOERROR) {
    if (hp->rcode == NXDOMAIN) {
      LOGMSG("'No such name' with id=%d", hp->id);
      an = expand_query(buf, len, c, answer, sizeof(answer) - 1, hp->id, &l);
      if (an) {
        answer[0] = 0;
        if      ((an->type == 0) && dns_ptr_handler)
          dns_ptr_handler(an->at, an->ndx, answer);
#ifdef WITH_IPINFO
        else if ((an->type == 1) && dns_txt_handler)
          dns_txt_handler(an->at, an->ndx, answer);
#endif
        /*summ*/ { if (an->type == 0) dns_replies[1]++; else if (an->type == 1) dns_replies[2]++; }
      }
    } else
      LOGRET("Response error %d", hp->rcode);
    return;
  }

  if (!(hp->ancount))
    LOGRET("No error returned, but no answer given");
  if (hp->qdcount != 1)
    LOGRET("Reply contains %d queries (must be 1)", hp->qdcount);
  if (c > eob)
    LOGRET("Reply too short");

  memset(answer, 0, sizeof(answer));
  if (!expand_query(buf, len, c, answer, sizeof(answer) - 1, hp->id, &l))
    return;
  LOGMSG("Response for %s", answer);

  c += l;
  if (c + 4 > eob)
    LOGRET("Query resource record truncated");
  { int type = 0; GETSHORT(type, c);
    if (type == T_PTR) dns_replies[1]++; /*summ*/
#ifdef WITH_IPINFO
    else if (type == T_TXT) dns_replies[2]++;
#endif
    else LOGRET("Unknown query type %u in reply", type); }

  c += INT16SZ; // skip class

  for (int i = hp->ancount + hp->nscount + hp->arcount; i; i--) {
    if (c > eob)
      LOGRET("Packet does not contain all specified records");
    memset(answer, 0, sizeof(answer));
    atndx_t *atndx = expand_query(buf, len, c, answer, sizeof(answer) - 1, hp->id, &l);
    c += l;
    if (c + 10 > eob)
      LOGRET("Truncated record");
    int type = 0;
    GETSHORT(type, c);
    c += INT16SZ; // skip class
    c += INT32SZ; // skip ttl
    int size = 0;
    GETSHORT(size, c);
    if (!size)
      LOGRET("Empty rdata");
    if (c + size > eob)
      LOGRET("Specified rdata length exceeds packet size");

    if (atndx && ((type == T_PTR) || (type == T_TXT))) { // answer to us
      memset(answer, 0, sizeof(answer));
      if (type == T_TXT) {
        l = *c;
        if ((l >= size) || (l <= 0))
          LOGRET("Broken TXT record (len=%d, size=%d)", l, size);
        { const char *data = (char*)(c + 1);
          int max = l; if ((size_t)max >= sizeof(answer)) max = sizeof(answer) - 1;
#ifdef HAVE_STRLCPY
          strlcpy(answer, data, max);
#else
          strncpy(answer, data, max);
          answer[max] = 0;
#endif
        }
      } else {
        l = dn_expand(buf, buf + len, c, answer, sizeof(answer) - 1);
        if (l < 0) LOGRET("dn_expand() failed while expanding domain");
      }
      LOGMSG("Answer[%d] %.*s", l, l, answer);
      if      ((atndx->type == 0) && dns_ptr_handler)
        dns_ptr_handler(atndx->at, atndx->ndx, answer);
#ifdef WITH_IPINFO
      else if ((atndx->type == 1) && dns_txt_handler)
        dns_txt_handler(atndx->at, atndx->ndx, answer);
#endif
      return; // let's take the first answer
    }
    c += size;
  }
}


// Validate if this server is actually one we sent to
static bool validate_ns(int family) {
#ifdef ENABLE_IPV6
  if (family == AF_INET6) {
    bool local = !addr6exist(&sa_from.S6ADDR);
    for (int i = 0; i < nscount6; i++) {
      struct in6_addr *addr = &nsaddrs6[i].sin6_addr;
      if (addr6equal(addr, &sa_from.S6ADDR))
        return true;
      if (local && addr6exist(addr))
        return true;
    }
  } else if (family == AF_INET)
#endif
  { bool local = !addr4exist(&sa_from.S_ADDR);
    for (int i = 0; i < nscount; i++) {
      struct in_addr *addr = &nsaddrs[i].sin_addr;
      if (addr4equal(addr, &sa_from.S_ADDR))
        return true;
      if (local && addr4exist(addr))
        return true;
    }
  } return false;
}

void dns_parse(int fd, int family) {
  uint8_t buf[PACKETSZ];
  socklen_t fromlen = sizeof(sa_from);
  ssize_t r = recvfrom(fd, buf, sizeof(buf), 0, &sa_from.sa, &fromlen);
  if (r > 0) {
    if (validate_ns(family)) dns_parse_reply(buf, r);
    else LOGRET("Reply from unknown source");
  } else if (r < 0) WARN("recvfrom(fd=%d)", fd);
}

