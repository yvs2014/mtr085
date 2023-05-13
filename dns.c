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

#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "config.h"
#include "mtr.h"
#include "net.h"
#include "dns.h"

#if defined(LOG_DNS) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_DNS) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "macros.h"

#ifdef ENABLE_IPV6
#ifdef __GLIBC__
#define NSSOCKADDR6(i) (myres._u._ext.nsaddrs[i])
#elif defined(__OpenBSD__)
#define NSSOCKADDR6(i) ((struct sockaddr_in6 *) &(_res_ext.nsaddr_list[i]))
#else
#define NSSOCKADDR6(i) (&(myres._u._ext.ext->nsaddrs[i].sin6))
#endif
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__sun) || defined(__HAIKU__)
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

#ifdef HAVE_RES_NMKQUERY
struct __res_state myres;
#define MYRES_INIT(res) res_ninit(&res)
#define MYRES_CLOSE(res) res_nclose(&res)
#define MYRES_QUERY(res, ...) res_nmkquery(&res, __VA_ARGS__)
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

// external callbacks for T_PTR and T_TXT replies
//   first one is used by net-module
//   and second one - by ipinfo-module
void (*dns_ptr_handler)(int at, int ndx, const char* answer);
void (*dns_txt_handler)(int at, int ndx, const char* answer);
//

static bool resolv_ready;
static bool dns_ready;
static int resfd = -1;
#ifdef ENABLE_IPV6
static int resfd6 = -1;
#endif

#ifdef ENABLE_IPV6
static struct sockaddr_storage from_sastruct;
static struct sockaddr_in6 *from6 = (struct sockaddr_in6 *) &from_sastruct;
#else
static struct sockaddr_in from_sastruct;
#endif
static struct sockaddr_in *from4 = (struct sockaddr_in *) &from_sastruct;
static struct sockaddr *from = (struct sockaddr *) &from_sastruct;

int dns_wait(int family) {
 return dns_ready ? (
#ifdef ENABLE_IPV6
  (family == AF_INET6) ? resfd6 :
#endif
  resfd) : -1;
}

static int dns_mkquery(int op, const char *dname, int class, int type, const uint8_t *data, int datalen,
  const uint8_t *newrr, uint8_t *buf, int buflen) {
  return MYRES_QUERY(myres, op, dname, class, type, data, datalen, newrr, buf, buflen);
}

static bool init_resolv(void) {
  if (!resolv_ready) {
    if (MYRES_INIT(myres) >= 0) {
      if (myres.nscount) {
        myres.options |= RES_DEFAULT;
        myres.options &= ~(RES_DNSRCH | RES_DEFNAMES);
        resolv_ready = true;
      } else {
        WARNX("No defined nameservers");
        MYRES_CLOSE(myres);
      }
    } else WARN("res_init");
  }
  return resolv_ready;
}

static bool open_sockets(void) {
  if (resfd < 0) {
    if ((resfd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
      /*summ*/ sum_sock[0]++;
    else
      WARN("socket");
  }
#ifdef ENABLE_IPV6
  if (resfd6 < 0) {
    if ((resfd6 = socket(AF_INET6, SOCK_DGRAM, 0)) >= 0)
      /*summ*/ sum_sock[0]++;
    else
      LOGMSG("socket6");
  }
#endif
  return (resfd >= 0)
#ifdef ENABLE_IPV6
     || (resfd6 >= 0)
#endif
  ;
}

bool dns_open(void) {
  if (init_resolv())
    dns_ready = open_sockets();
  LOGMSG_("%s", dns_ready ? "ok" : "failed");
  return dns_ready;
}

void dns_close(void) {
  if (dns_ready) { // close own sockets
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
    dns_ready = false;
    LOGMSG("ok");
  }
  // res_close()
  if (resolv_ready) {
    MYRES_CLOSE(myres);
    resolv_ready = false;
  }
}

#ifdef ENABLE_IPV6
// Returns an ip6.arpa character string
static void ip2arpa6(const uint8_t *p, char *buf, int sz, const char *suff) {
  int l = 0;
  for (int i = 0xf; i >= 0; i--) {
    l += snprintf(buf + l, sz - l, "%x.%x.", p[i] & 0xf, p[i] >> 4);
    if (l >= sz) return;
  }
  snprintf(buf + l, sz - l, "%s", suff);
}
#endif

char* ip2arpa(ip_t *ip, const char *suff4, const char *suff6) {
  static char lqbuf[NAMELEN];
  uint8_t *p = (uint8_t*)ip;
#ifdef ENABLE_IPV6
  if (af == AF_INET6) ip2arpa6(p, lqbuf, sizeof(lqbuf), suff6 ? suff6 : ARPA6_SUFFIX); else
#endif
  snprintf(lqbuf, sizeof(lqbuf), "%d.%d.%d.%d.%s", p[3], p[2], p[1], p[0], suff4 ? suff4 : ARPA4_SUFFIX);
  return lqbuf;
}


int dns_send_query(int at, int ndx, const char *qstr, int type) {
  static uint8_t req_buf[PACKETSZ];
  if (!dns_ready)
    return -1;
  int len = dns_mkquery(QUERY, qstr, C_IN, type, NULL, 0, NULL, req_buf, sizeof(req_buf));
  if (len < 0) {
    WARN_("[%d:%d type=%d]", at, ndx, type);
    LOG_RE_(-1, "[%d:%d type=%d] failed", at, ndx, type);
  }

  HEADER *hp = (HEADER*)req_buf;
  hp->id = str2hint(qstr, at, ndx);
  LOGMSG_("[%d:%d type=%d id=%d]: %s", at, ndx, type, hp->id, qstr);

  for (int i = 0; i < myres.nscount; i++) {
    int re;
#ifdef ENABLE_IPV6
    if (myres.nsaddr_list[i].sin_family == AF_INET6)
      re = sendto(resfd6, req_buf, len, 0, (struct sockaddr *)NSSOCKADDR6(i), sizeof(struct sockaddr_in6));
    else
#endif
      re = sendto(resfd, req_buf, len, 0, (struct sockaddr *)&myres.nsaddr_list[i], sizeof(struct sockaddr));
    /*summ*/ { dns_queries[0]++; if (type == T_PTR) dns_queries[1]++; else if (type == T_TXT) dns_queries[2]++; }
    if (re >= 0) // one successful request is enough
      return re;
    LOGMSG_("[%d:%d type=%d id=%d] #%d: %s", at, ndx, type, hp->id, i, strerror(errno));
  }
  return -1;
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
      WARN_("[%d:%d]: strndup()", at, ndx);
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
  for (int t = 0; t < sizeof(query) / sizeof(query[0]); t++)
    if (query[t])
      if (!strncasecmp(query[t], q, MAXDNAME)) {
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

static atndx_t *expand_query(const uint8_t *packet, int psize, const uint8_t *dn, char *answer, int asize, uint16_t id, int *r) {
  *r = dn_expand(packet, packet + psize, dn, answer, asize);
  if (*r < 0)
    LOG_RE(NULL, "dn_expand() failed while expanding query domain");
  atndx_t *an = find_query(answer, id); // id as a hint
  if (!an)
    LOGMSG_("Unknown response with id=%u q=%s", id, answer);
  return an;
}


static void dns_parse_reply(uint8_t *buf, ssize_t len) {
  static char answer[MAXDNAME];

  if (len < (int)sizeof(HEADER))
    LOGRET("Packet smaller than standard header size");
  if (len == (int)sizeof(HEADER))
    LOGRET("Packet has empty body");
  HEADER *hp = (HEADER*)buf;

  LOGMSG_("got %zd bytes, id=%u at=%u ndx=%u", len, hp->id, ID2AT(hp->id), ID2NDX(hp->id));
  dns_replies[0]++; /*summ*/

  hp->qdcount = ntohs(hp->qdcount);
  hp->ancount = ntohs(hp->ancount);
  hp->nscount = ntohs(hp->nscount);
  hp->arcount = ntohs(hp->arcount);
//  LOGMSG_("qd:%u an:%u ns:%u ar:%u", hp->qdcount, hp->ancount, hp->nscount, hp->arcount);
  if (hp->tc)     // truncated packet
    LOGRET("Truncated packet");
  if (!hp->qr)    // not a reply
    LOGRET("Not a reply");
  if (hp->opcode) // non-standard query
    LOGRET("Invalid opcode");
  uint8_t *eob = buf + len;
  uint8_t *c = buf + sizeof(HEADER);
  int l;
  atndx_t *an;

  if (hp->rcode != NOERROR) {
    if (hp->rcode == NXDOMAIN) {
      LOGMSG_("'No such name' with id=%d", hp->id);
      if ((an = expand_query(buf, len, c, answer, sizeof(answer) - 1, hp->id, &l))) {
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
      LOGRET_("Response error %d", hp->rcode);
    return;
  }

  if (!(hp->ancount))
    LOGRET("No error returned, but no answer given");
  if (hp->qdcount != 1)
    LOGRET_("Reply contains %d queries (must be 1)", hp->qdcount);
  if (c > eob)
    LOGRET("Reply too short");

  memset(answer, 0, sizeof(answer));
  if (!(an = expand_query(buf, len, c, answer, sizeof(answer) - 1, hp->id, &l)))
    return;
  LOGMSG_("Response for %s", answer);

  c += l;
  if (c + 4 > eob)
    LOGRET("Query resource record truncated");
  { int type; GETSHORT(type, c); if (type == T_PTR) dns_replies[1]++; /*summ*/
#ifdef WITH_IPINFO
    else if (type == T_TXT) dns_replies[2]++;
#endif
    else LOGRET_("Unknown query type %u in reply", type); }

  c += INT16SZ;	// skip class

  for (int i = hp->ancount + hp->nscount + hp->arcount; i; i--) {
    if (c > eob)
      LOGRET("Packet does not contain all specified records");
    memset(answer, 0, sizeof(answer));
    an = expand_query(buf, len, c, answer, sizeof(answer) - 1, hp->id, &l);
    c += l;
    if (c + 10 > eob)
      LOGRET("Truncated record");
    int type;
    GETSHORT(type, c);
    c += INT16SZ;	// skip class
    c += INT32SZ;	// skip ttl
    int size;
    GETSHORT(size, c);
    if (!size)
      LOGRET("Empty rdata");
    if (c + size > eob)
      LOGRET("Specified rdata length exceeds packet size");

    if (an && ((type == T_PTR) || (type == T_TXT))) { // answer to us
      memset(answer, 0, sizeof(answer));
      if (type == T_TXT) {
        l = *c;
        if ((l >= size) || !l)
          LOGRET_("Broken TXT record (len=%d, size=%d)", l, size);
        int max = (l < sizeof(answer)) ? l : (sizeof(answer) - 1);
        strncpy(answer, (char*)(c + 1), max);
        answer[l] = 0;
	  } else if ((l = dn_expand(buf, buf + len, c, answer, sizeof(answer) - 1)) < 0)
        LOGRET("dn_expand() failed while expanding domain");
      LOGMSG_("Answer %.*s", l, answer);
      if      ((an->type == 0) && dns_ptr_handler)
        dns_ptr_handler(an->at, an->ndx, answer);
#ifdef WITH_IPINFO
      else if ((an->type == 1) && dns_txt_handler)
        dns_txt_handler(an->at, an->ndx, answer);
#endif
      return; // let's take the first answer
    }
    c += size;
  }
}


// Check to see if this server is actually one we sent to
static bool validate_ns(int family) {
#ifdef ENABLE_IPV6
  if (family == AF_INET6) {
    static struct in6_addr localhost6 = IN6ADDR_LOOPBACK_INIT;
    bool local = addr6equal(&(from6->sin6_addr), &localhost6);
    for (int i = 0; i < myres.nscount; i++) {
      if (addr6equal(&(NSSOCKADDR6(i)->sin6_addr), &(from6->sin6_addr)))
        return true;
      if (local && addr6equal(&(NSSOCKADDR6(i)->sin6_addr), &unspec_addr))
        return true;
    }
  } else
#endif
  {
    static struct in_addr localhost4 = { .s_addr = INADDR_LOOPBACK };
    bool local = addr4equal(&(from4->sin_addr), &localhost4);
    for (int i = 0; i < myres.nscount; i++) {
      if (addr4equal(&(myres.nsaddr_list[i].sin_addr), &(from4->sin_addr)))
        return true;
      if (local && addr4equal(&(myres.nsaddr_list[i].sin_addr), &unspec_addr))
        return true;
    }
  }
  return false;
}

void dns_parse(int fd, int family) {
  static uint8_t buf[PACKETSZ];
  static socklen_t fromlen = sizeof(from_sastruct);
  ssize_t r = recvfrom(fd, buf, sizeof(buf), 0, from, &fromlen);
  if (r > 0) {
    if (validate_ns(family))
      dns_parse_reply(buf, r);
    else
      LOGRET("Reply from unknown source");
  } else
    WARN_("recvfrom(fd=%d)", fd);
}

