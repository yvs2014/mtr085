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
#include <string.h>
#include <strings.h>

#if defined(LOG_DNS) && !defined(LOGMOD)
#include <errno.h>
#define LOGMOD
#endif
#if !defined(LOG_DNS) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "common.h"

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
#include "nls.h"
#include "aux.h"

#ifdef ENABLE_IPV6
#if defined(__GLIBC__) || defined(__linux__)
#define NSADDR6(i) (myres._u._ext.nsaddrs[i])
#elif defined(__OpenBSD__)
#define NSADDR6(i) ((struct sockaddr_in6 *)&_res_ext.nsaddr_list[i])
#else
#define NSADDR6(i) (&myres._u._ext.ext->nsaddrs[i].sin6)
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

static uint nscount4;
static struct sockaddr_in  nsaddr4[MAXNS];
#ifdef ENABLE_IPV6
static uint nscount6;
static struct sockaddr_in6 nsaddr6[MAXNS];
#endif

#ifdef HAVE_RES_NMKQUERY
static struct __res_state myres;
#define MYRES_INIT(res) res_ninit(&(res))
#define MYRES_INIT_STR "res_ninit()"
#define MYRES_CLOSE(res) res_nclose(&(res))
#define MYRES_QUERY(res, ...) res_nmkquery(&(res), __VA_ARGS__)
#else
extern struct __res_state _res;
#define myres _res
#define MYRES_INIT(res) res_init()
#define MYRES_INIT_STR "res_init()"
#define MYRES_CLOSE(res)
#define MYRES_QUERY(res, ...) res_mkquery(__VA_ARGS__)
#endif

#define ARPA4_SUFFIX "in-addr.arpa"
#define ARPA6_SUFFIX "ip6.arpa"

#ifdef LOGMOD
  #ifdef __GNUC__
    #define DIAG_DEPR_SUPPRESS _Pragma("GCC diagnostic push") \
      _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
    #define DIAG_RESTORE _Pragma("GCC diagnostic pop")
  #elif __clang__
    #define DIAG_DEPR_SUPPRESS _Pragma("clang diagnostic push") \
      _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
    #define DIAG_RESTORE _Pragma("clang diagnostic pop")
  #endif
  #define RESDEB_ON  DIAG_DEPR_SUPPRESS
  #define RESDEB_OFF DIAG_RESTORE
#else
  #define RESDEB_ON
  #define RESDEB_OFF
#endif

// global
uint dns_queries[3];     // number of queries (sum, ptr, txt)
uint dns_replies[3];     // number of replies (sum, ptr, txt)
t_sockaddr *custom_res;  // -N option

// external callbacks for 'ns_t_ptr' and 'ns_t_txt' replies
//   first one by net-module
//   second by ipinfo-module
dns_handler_fn dns_ptr_handler, dns_txt_handler;
//

static bool dns_ready;
static int resfd4 = -1;
#ifdef ENABLE_IPV6
static int resfd6 = -1;
#endif

static t_sockaddr sa_from;

int dns_wait(int family) {
 return dns_ready ? (
#ifdef ENABLE_IPV6
  (family == AF_INET6) ? resfd6 :
#endif
  resfd4) : -1;
}

static bool dns_sockets(void) {
  if (nscount4 && (resfd4 < 0)) {
    resfd4 = socket(AF_INET, SOCK_DGRAM, 0);
    if (resfd4 < 0)
      warn("%s", "dns-socket4");
    else
      /*summ*/ sum_sock[0]++;
  }
#ifdef ENABLE_IPV6
  if (nscount6 && (resfd6 < 0)) {
    resfd6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (resfd6 < 0)
      LOGMSG("%s", "dns-socket6");
    else
      /*summ*/ sum_sock[0]++;
  }
#endif
  return
#ifdef ENABLE_IPV6
    (nscount6 && (resfd6 >= 0)) ||
#endif
    (nscount4 && (resfd4 >= 0));
}

#define VALIDATE_NS4(resaddr) { \
  if ((resaddr) && ((resaddr)->sin_family  == AF_INET)  && addr4exist(&(resaddr)->sin_addr))  \
    memcpy(&nsaddr4[nscount4++], (resaddr), sizeof(nsaddr4[0])); }
#define VALIDATE_NS6(resaddr) { \
  if ((resaddr) && ((resaddr)->sin6_family == AF_INET6) && addr6exist(&(resaddr)->sin6_addr)) \
    memcpy(&nsaddr6[nscount6++], (resaddr), sizeof(nsaddr6[0])); }

static inline void dns_nses(void) {
  // note1: res is empty with musl libc, .nscount6 is 0 with glibc
  // note2: res.options are from resolv.conf unless nsserver is defined
  if (custom_res) {
    myres.options = RES_RECURSE;
    if (custom_res->SA_AF == AF_INET)
      memcpy(&nsaddr4[nscount4++], custom_res, sizeof(nsaddr4[0]));
#ifdef ENABLE_IPV6
    else if (custom_res->SA_AF == AF_INET6)
      memcpy(&nsaddr6[nscount6++], custom_res, sizeof(nsaddr6[0]));
#endif
  } else {
#ifdef ENABLE_IPV6
    for (uint i = 0; (i < MAXNS) && (nscount6 < MAXNS); i++)
      VALIDATE_NS6(NSADDR6(i));
#endif
    for (uint i = 0; (i < MAXNS) && (nscount4 < MAXNS); i++)
      VALIDATE_NS4(&myres.nsaddr_list[i]);
  }
  dns_ready =
#ifdef ENABLE_IPV6
    (nscount6 > 0) ||
#endif
    (nscount4 > 0);
  if (!dns_ready) {
    warnx("%s", NODNS_ERR);
    MYRES_CLOSE(myres);
  }
}

#ifdef LOGMOD
static inline void dns_open_finlog(void) {
  LOGMSG("%s", dns_ready ? "ok" : "failed");
  LOGMSG("nscount4=%u", nscount4);
  char buff[MAX_ADDRSTRLEN];
  for (uint i = 0; i < nscount4; i++)
    if (inet_ntop(nsaddr4[i].sin_family, &nsaddr4[i].sin_addr, buff, sizeof(buff)))
      LOGMSG("ns4#%u: %s:%u (af=%u)", i, buff, ntohs(nsaddr4[i].sin_port), nsaddr4[i].sin_family);
  LOGMSG("nscount6=%d", nscount6);
  for (uint i = 0; i < nscount6; i++)
    if (inet_ntop(nsaddr6[i].sin6_family, &nsaddr6[i].sin6_addr, buff, sizeof(buff)))
      LOGMSG("ns6#%u: [%s]:%u (af=%u)", i, buff, ntohs(nsaddr6[i].sin6_port), nsaddr6[i].sin6_family);
}
#endif

bool dns_open(void) {
  if (dns_ready)
    return true;
  if (MYRES_INIT(myres) < 0)
    warn("%s", MYRES_INIT_STR);
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
  if (resfd4 >= 0) {
    close(resfd4);
    /*summ*/ sum_sock[1]++;
    resfd4 = -1;
  }
#ifdef ENABLE_IPV6
  if (resfd6 >= 0) {
    close(resfd6);
    /*summ*/ sum_sock[1]++;
    resfd6 = -1;
  }
#endif
  if (custom_res) {
    free(custom_res);
    custom_res = NULL;
  }
  MYRES_CLOSE(myres);
  LOGMSG("%s", "ok");
}

#ifdef ENABLE_IPV6
#define HEXMASK 0xf
// fill ip6.arpa str
static void ip2arpa6(uint size, char buff[size], const uint8_t addr6[16], const char *suff) NONNULL(2, 3, 4);
static void ip2arpa6(uint size, char buff[size], const uint8_t addr6[16], const char *suff) {
  uint len = 0;
  for (int i = HEXMASK; (i >= 0) && (len < size); i--) {
    int inc = snprinte(buff + len, size - len, "%x.%x.", addr6[i] & HEXMASK, addr6[i] >> 4);
    if (inc <= 0)
      break;
    len += inc;
  }
  if (len < size)
    snprinte(buff + len, size - len, "%s", suff);
}
#endif

void ip2arpa(uint size, char buff[size], const t_ipaddr *ipaddr,
  const char *suff4, const char *suff6) // NONNULL(2, 3)
{
#ifdef ENABLE_IPV6
  if (af == AF_INET6)
    ip2arpa6(size, buff, ipaddr->in6.s6_addr, suff6 ? suff6 : ARPA6_SUFFIX);
  else
#endif
  { snprinte(buff, size, "%d.%d.%d.%d.%s",
      ipaddr->s_addr8[3], ipaddr->s_addr8[2], ipaddr->s_addr8[1], ipaddr->s_addr8[0],
     suff4 ? suff4 : ARPA4_SUFFIX); }
}

static int send2ns(int fd, uint ns_max,  const struct sockaddr *ns_list, socklen_t ns_addrlen,
  uint8_t *query, uint len, uint *qcnt) NONNULL(3, 5);
static int send2ns(int fd, uint ns_max,  const struct sockaddr *ns_list, socklen_t ns_addrlen,
  uint8_t *query, uint len, uint *qcnt)
{
  for (uint i = 0; i < ns_max; i++, ns_list += ns_addrlen) {
    int rc = sendto(fd, query, len, 0, ns_list, ns_addrlen);
    if (rc >= 0) {
      /*summ*/ dns_queries[0]++; if (qcnt) (*qcnt)++;
      return rc;
    }
    LOGMSG("[id=%u ns#%u] sendto() errno=%d: %s", ns_get16(query), i, errno, strerror(errno));
  }
  return -1;
}

int dns_send_query(int at, int ndx, const char *qstr, int type) {
  static uint8_t ns_query_buff[NS_PACKETSZ];
  if (!dns_ready)
    return -1;
  int len = MYRES_QUERY(myres, ns_o_query, qstr, ns_c_in, type, NULL, 0, NULL,
    ns_query_buff, sizeof(ns_query_buff));
  if (len < 0) {
    WARN("[%d:%d type=%d]", at, ndx, type);
RESDEB_ON
    LOGRET_RC(-1, "[%d:%d type=%s] failed", at, ndx, p_type(type));
RESDEB_OFF
  }
  //
  ns_put16(str2hint(qstr, at, ndx), ns_query_buff);
RESDEB_ON
  LOGMSG("[%d:%d type=%s id=%u]: %s", at, ndx, p_type(type), ns_get16(ns_query_buff), qstr);
RESDEB_OFF
  //
  uint *qcnt =
    (type == ns_t_ptr) ? &dns_queries[1] :
    (type == ns_t_txt) ? &dns_queries[2] :
    NULL;
  int rc = send2ns(resfd4, nscount4, (struct sockaddr *)nsaddr4, sizeof(nsaddr4[0]), ns_query_buff, len, qcnt);
#ifdef ENABLE_IPV6
  if (rc < 0)
      rc = send2ns(resfd6, nscount6, (struct sockaddr *)nsaddr6, sizeof(nsaddr6[0]), ns_query_buff, len, qcnt);
#endif
  return rc;
}
#undef SENDTONS

inline const char *dns_ptr_cache(uint at, uint ndx) {
  return addr_exist(&IP_AT_NDX(at, ndx)) ? RPTR_AT_NDX(at, ndx) : NULL;
}

const char *dns_ptr_lookup(int at, int ndx) {
  if (!run_opts.dns) // not enabled
    return NULL;
  if (!addr_exist(&IP_AT_NDX(at, ndx))) // on the off chance
    return NULL;
  if (RPTR_AT_NDX(at, ndx)) // already known
    return RPTR_AT_NDX(at, ndx);

  // set query string if not yet (setting a new ip, free this query)
  if (!QPTR_AT_NDX(at, ndx)) {
    char query[NAMELEN] = {0};
    ip2arpa(sizeof(query), query, &IP_AT_NDX(at, ndx), NULL, NULL);
    QPTR_AT_NDX(at, ndx) = strndup(query, sizeof(query));
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
    dns_send_query(at, ndx, QPTR_AT_NDX(at, ndx), ns_t_ptr);
  }
  return NULL;
}


static atndx_t *get_qatn(const char* q, int at, int ndx) {
  const char *query[] = { QPTR_AT_NDX(at, ndx)
#ifdef WITH_IPINFO
   , QTXT_AT_NDX(at, ndx)
#endif
  };
  int qmax = ARRAY_LEN(query); // 1 or 2
  for (int t = 0; t < qmax; t++)
    if (query[t] && !strncasecmp(query[t], q, NS_MAXDNAME)) {
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

static atndx_t* find_query_with_id(const char *query, uint16_t id) NONNULL(1);
static atndx_t* find_query_with_id(const char *query, uint16_t id) {
  atndx_t *an = find_query(query, id); // id as a hint
  if (!an)
    LOGMSG("Unknown response with id=%u q=%s", id, query);
  return an;
}

#ifdef LOGMOD
static void dns_printrr(const ns_msg *msg, const ns_rr *rr) NONNULL(1, 2);
static void dns_printrr(const ns_msg *msg, const ns_rr *rr) {
  char buff[NS_MAXDNAME * 2] = {0};
RESDEB_ON
  ns_sprintrr(msg, rr, NULL, NULL, buff, sizeof(buff));
RESDEB_OFF
  LOGMSG("%.*s", (int)sizeof(buff), buff);
}
#else
#define dns_printrr(msg, rr) NOOP
#endif

static void dns_got_nosuch_name(const char *query, uint16_t id) NONNULL(1);
static void dns_got_nosuch_name(const char *query, uint16_t id) {
  atndx_t *an = find_query_with_id(query, id);
  if (an) {
    char answer[NS_MAXDNAME] = {0};
    if      (dns_ptr_handler && (an->type == 0))
      dns_ptr_handler(an->at, an->ndx, answer, 1);
    else if (dns_txt_handler && (an->type == 1))
      dns_txt_handler(an->at, an->ndx, answer, 1);
    /*summ*/ { if (an->type == 0) dns_replies[1]++; else if (an->type == 1) dns_replies[2]++; }
  }
}

static void dns_handle_ptr(int at, int ndx, dns_handler_fn handler, const ns_msg *msg, const ns_rr *rr) NONNULL(3, 4, 5);
static void dns_handle_ptr(int at, int ndx, dns_handler_fn handler, const ns_msg *msg, const ns_rr *rr) {
  char answer[NS_MAXDNAME] = {0};
  int rc = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg), ns_rr_rdata(*rr), answer, sizeof(answer) - 1);
  if (rc < 0)
    LOGMSG("failed expanding domain: errno=%d (%s)", errno, strerror(errno));
  else {
    uint bound = sizeof(answer) - 1;
    uint len = ((uint)rc < bound) ? (uint)rc : bound;
    answer[len] = 0; // be sure
    LOGMSG("%.*s", len, answer);
    handler(at, ndx, answer, strnlen(answer, len)); // answer can be shorter than 'len'
  }
}

static void dns_handle_txt(int at, int ndx, dns_handler_fn handler, const uint8_t *rdata, int rlen, char delim) NONNULL(3, 4);
static void dns_handle_txt(int at, int ndx, dns_handler_fn handler, const uint8_t *rdata, int rlen, char delim) {
  char answer[NS_MAXDNAME] = {0};
  char *cursor = answer;
  int alen = sizeof(answer) - 1;
  uint txtlen = 0, chunkno = 0;
  while ((alen > 0) && (rlen > 0)) {
    // every chunk
    if (delim && chunkno) {
      if (alen > 0) {
        *cursor++ = delim;
        alen--;
        txtlen++;
      } else {
        LOGMSG("TXT record buffer, chunk=%u, delimiter='%c': %s", chunkno, delim, strerror(EMSGSIZE));
        return;
      }
    }
    uint8_t len = *rdata++;
    rlen--;
    if (len && (len <= rlen)) {
      if (len > alen) {
        LOGMSG("TXT record buffer: %s", strerror(EMSGSIZE));
        return;
      }
      memcpy(cursor, rdata, len);
      cursor += len;
      alen   -= len;
      rdata  += len;
      rlen   -= len;
      txtlen += len;
    } else {
      LOGMSG("%s", "Broken TXT record");
      return;
    }
    chunkno++;
  }
  if (txtlen >= sizeof(answer))
    txtlen = sizeof(answer) - 1;
#ifdef LOGMOD
  LOGMSG("got in %u chunk%s: %.*s", chunkno, chunkno > 1 ? "s" : "", txtlen, answer);
  if (delim)
    LOGMSG("chunks delimited with '%c'", delim);
#endif
  handler(at, ndx, answer, txtlen);
}

static void dns_extract_answer(ns_msg *msg, int section) NONNULL(1);
static void dns_extract_answer(ns_msg *msg, int section) {
  int count = ns_msg_count(*msg, section);
  for (int i = 0; i < count; i++) {
    ns_rr rr = {0};
    if (ns_parserr(msg, section, i, &rr) >= 0) {
      int type = ns_rr_type(rr);
      if ((type == ns_t_ptr) || (type == ns_t_txt)) {
        atndx_t *an = find_query_with_id(ns_rr_name(rr), ns_msg_id(*msg));
        if (an) {
          dns_printrr(msg, &rr);
          // TODO: an->type [ns_t_ptr, ns_t_txt, ...]
          if      ((type == ns_t_ptr) && (an->type == 0) && dns_ptr_handler) {
            dns_handle_ptr(an->at, an->ndx, dns_ptr_handler, msg, &rr);
            /*summ*/ dns_replies[1]++;
          } else if ((type == ns_t_txt) && (an->type == 1) && dns_txt_handler) {
            const uint8_t *rdata = ns_rr_rdata(rr);
            uint16_t rlen = ns_rr_rdlen(rr);
            if (rdata && rlen)
              dns_handle_txt(an->at, an->ndx, dns_txt_handler, rdata, rlen/*uint16->int32*/, VSLASH);
            /*summ*/ dns_replies[2]++;
          }
          // let's take the first record and break
          return;
        }
      }
    }
  }
#ifdef WITH_IPINFO
  LOGMSG("Neither '%s' nor '%s' query type", "ns_t_ptr", "ns_t_txt");
#else
  LOGMSG("Not '%s' query type", "ns_t_txt");
#endif
}

static bool dns_query_checkin(ns_msg *msg) NONNULL(1);
static bool dns_query_checkin(ns_msg *msg) {
  bool fail = !ns_msg_count(*msg, ns_s_an);
  if (fail)
    LOGMSG("%s", "No answer");
  else {
    uint16_t qd = ns_msg_count(*msg, ns_s_qd);
    fail = (qd != 1);
    if (fail)
      LOGMSG("More than one query: %u", qd);
    else {
      ns_rr rr = {0};
      fail = (ns_parserr(msg, ns_s_qd, 0, &rr) < 0);
      if (fail)
        LOGMSG("Parsing query: %s", strerror(errno));
      else {
        fail = !find_query_with_id(ns_rr_name(rr), ns_msg_id(*msg));
        if (fail)
          LOGMSG("Not our request: %s", ns_rr_name(rr));
        else
          LOGMSG("Response for %s", ns_rr_name(rr));
      }
    }
  }
  return !fail;
}

static bool dns_qd_okay(ns_msg *msg) NONNULL(1);
static bool dns_qd_okay(ns_msg *msg) {
  bool fail = ns_msg_getflag(*msg, ns_f_tc);
  if (fail)
    LOGMSG("%s", "Truncated packet");
  else {
    fail = !ns_msg_getflag(*msg, ns_f_qr);
    if (fail)
      LOGMSG("%s", "Not a reply");
    else {
      int opcode = ns_msg_getflag(*msg, ns_f_opcode);
      fail = opcode;
      if (fail)
        LOGMSG("Invalid opcode(%d)", opcode);
    }
  }
  return !fail;
}

static void dns_parse_reply(const uint8_t *data, size_t len) NONNULL(1);
static void dns_parse_reply(const uint8_t *data, size_t len) {
  dns_replies[0]++; /*summ*/
  ns_msg msg = {0};
  if (ns_initparse(data, len, &msg) < 0)
    LOGMSG("Parse reply: %s", strerror(errno));
  else {
    LOGMSG("got %zu bytes, id=%u at=%u ndx=%u, counts(qd:%u an:%u ns:%u ar:%u)",
      len, ns_msg_id(msg), ID2AT(ns_msg_id(msg)), ID2NDX(ns_msg_id(msg)),
      ns_msg_count(msg, ns_s_qd),
      ns_msg_count(msg, ns_s_an),
      ns_msg_count(msg, ns_s_ns),
      ns_msg_count(msg, ns_s_ar));
    if (dns_qd_okay(&msg)) {
      int rcode = ns_msg_getflag(msg, ns_f_rcode);
      if (rcode == ns_r_noerror) {
        if (dns_query_checkin(&msg))
          dns_extract_answer(&msg, ns_s_an);
      } else {
        if (rcode != ns_r_nxdomain)
          LOGMSG("Response error %d", rcode);
        else {
          LOGMSG("'No such name' with id=%d", ns_msg_id(msg));
          ns_rr rr = {0};
          if ((ns_msg_count(msg, ns_s_qd) > 0) && (ns_parserr(&msg, ns_s_qd, 0, &rr) >= 0))
            dns_got_nosuch_name(ns_rr_name(rr), ns_msg_id(msg));
        }
      }
    }
  }
}

// Validate if this server is actually one we sent to
static bool validns(int family) {
#ifdef ENABLE_IPV6
  if        (family == AF_INET6) {
    bool local = !addr6exist(&sa_from.S6ADDR);
    for (uint i = 0; i < nscount6; i++) {
      struct in6_addr *addr = &nsaddr6[i].sin6_addr;
      if (addr6equal(addr, &sa_from.S6ADDR))
        return true;
      if (local && addr6exist(addr))
        return true;
    }
  } else if (family == AF_INET)
#endif
  { bool local = !addr4exist(&sa_from.S_ADDR);
    for (uint i = 0; i < nscount4; i++) {
      struct in_addr *addr = &nsaddr4[i].sin_addr;
      if (addr4equal(addr, &sa_from.S_ADDR))
        return true;
      if (local && addr4exist(addr))
        return true;
    }
  } return false;
}

void dns_parse(int fd, int family) {
  uint8_t packet[NS_PACKETSZ];
  socklen_t fromlen = sizeof(sa_from);
  ssize_t r = recvfrom(fd, packet, sizeof(packet), 0, &sa_from.sa, &fromlen);
  if (r > 0) {
    if (validns(family))
      dns_parse_reply(packet, r);
    else
      LOGMSG("%s", "Reply from unknown source");
  } else if (r < 0)
    warn("recvfrom(fd=%d)", fd);
}

