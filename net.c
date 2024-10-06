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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <assert.h>

#include "config.h" // IWYU pragma: keep

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif

#ifdef LIBCAP
#include <sys/capability.h>
#endif

#include "common.h"
#include "net.h"
#include "aux.h"
#include "mtr-poll.h"
#include "display.h"

#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef OUTPUT_FORMAT_RAW
#include "report.h"
#endif

#ifdef HAVE_ARC4RANDOM_UNIFORM
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#define RANDUNIFORM(base) arc4random_uniform(base)
#else // original version
#define RANDUNIFORM(base) ((base - 1) * (rand() / (RAND_MAX + 0.1)))
#endif

// no common field names
struct PACKIT _iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t ihl:4;
  uint8_t ver:4;
#elif BYTE_ORDER == BIG_ENDIAN
  uint8_t ver:4;
  uint8_t ihl:4;
#else
#error "Undefined byte order"
#endif
  uint8_t tos;
  uint16_t len, id, frag;
  uint8_t ttl, proto;
  uint16_t sum;
  uint32_t saddr, daddr;
}; /* must be 20 bytes */

// no common field names
struct PACKIT _icmphdr {
  uint8_t type, code;
  uint16_t sum, id, seq;
}; /* must be 8 bytes */

#ifndef ICMP_TIME_EXCEEDED  // not defined on old systems
#define ICMP_TIME_EXCEEDED  11
#endif

// struct tcphdr /* common because RFC793 */
// struct udphdr /* common because RFC768 */

// udp4 pseudo header
struct PACKIT _udpph {
  uint32_t saddr, daddr;
  uint8_t zero, proto;
  uint16_t len;
}; /* must be 12 bytes */


#ifdef WITH_MPLS
struct PACKIT icmpext_struct { // RFC4884
#if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t res:4;
  uint8_t ver:4;
#elif BYTE_ORDER == BIG_ENDIAN
  uint8_t ver:4;
  uint8_t res:4;
#else
#error "Undefined byte order"
#endif
  uint8_t rest;
  uint16_t sum;
}; /* must be 4 bytes */

struct PACKIT icmpext_object { // RFC4884
  uint16_t len;
  uint8_t class;
  uint8_t type;
}; /* must be 4 bytes */

#define ICMP_EXT_VER        2
#define ICMP_EXT_CLASS_MPLS 1
#define ICMP_EXT_TYPE_MPLS  1

#define IES_SZ sizeof(struct icmpext_struct)
#define IEO_SZ sizeof(struct icmpext_object)
#define LAB_SZ sizeof(mpls_label_t)
#define MPLSMIN 120 // min after: [ip] icmp ip

#define MPLSFNTAIL(arg) , arg
#else
#define MPLSFNTAIL(arg)
#endif /*MPLS*/


#define LO_UDPPORT 33433	// start from LO_UDPPORT+1
#define UDPPORTS 90		// go thru udp:33434-33523 acl
#define TCP_DEFAULT_PORT 80

#define SET_UDP_UH_PORTS(uh, s, d) { (uh)->uh_sport = htons(s); (uh)->uh_dport = htons(d); }

// NOTE: don't forget to include sys/param.h
#if   defined(__FreeBSD_version)
#if __FreeBSD_version >= 1100000
#define IPLEN_RAW(sz) htons(sz)
#endif
#elif defined(__OpenBSD__)
#define IPLEN_RAW(sz) htons(sz)
#elif defined(__HAIKU__)
#define IPLEN_RAW(sz) htons(sz)
#ifndef IPV6_CHECKSUM
#define IPV6_CHECKSUM 7
#endif
#else
#define IPLEN_RAW(sz) sz
#endif

#define EXIT(s) { int e = errno; display_close(true); ERRX_(e, "%s: %s", s, strerror(e)); }

#define CLOSE(fd) if ((fd) >= 0) { close(fd); fd = -1; /*summ*/ sum_sock[1]++; }

#define FAIL_WITH_WARNX(rcode, fd, fmt, ...) { last_neterr = rcode; \
  display_clear(); CLOSE(fd); \
  WARNX_(fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
  snprintf(neterr_txt, ERRBYFN_SZ, fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
  LOG_RE_(false, fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
}

#define FAIL_WITH_WARN(fd, fmt, ...) FAIL_WITH_WARNX(errno, fd, fmt, __VA_ARGS__)

struct sequence {
  int at;
  bool transit;
  struct timespec time;
#ifdef CURSESMODE
  int saved_seq;
#endif
};

// global vars
t_ipaddr unspec_addr; // 0
bool  (*addr_exist)(const void *a); // true if not 0
bool  (*addr_equal)(const void *a, const void *b);
void* (*addr_copy)(void *dst, const void *src);
int af = AF_INET;  // default address family
struct nethost host[MAXHOST];
char localaddr[MAX_ADDRSTRLEN];
unsigned long net_queries[4]; // number of queries (sum, icmp, udp, tcp)
unsigned long net_replies[4]; // number of replies (sum, icmp, udp, tcp)
enum { QR_SUM = 0 /*sure*/, QR_ICMP, QR_UDP, QR_TCP };
//


/* How many queries to unknown hosts do we send?
 * It limits the amount of traffic generated if a host is not reachable
 */
#define MAX_UNKNOWN_HOSTS 10

static int bitpattern;
static int packetsize;
static struct sequence seqlist[MAXSEQ];

static int sendsock4 = -1;
static int recvsock4 = -1;
#ifdef ENABLE_IPV6
static int sendsock6 = -1;
static int sendsock6_icmp = -1;
//static int sendsock6_udp = -1;
//static int sendsock6_tcp = -1;
static int recvsock6 = -1;
#endif
static int sendsock = -1;
static int recvsock = -1;

static t_sockaddr lsa, rsa; // losal and remote sockaddr
static t_ipaddr *remote_ipaddr;

static int echo_reply, time_exceed, dst_unreach;

static size_t ipicmphdr_sz = sizeof(struct _icmphdr);
static size_t minfailsz = sizeof(struct _icmphdr);
static size_t hdr_minsz;
static size_t iphdr_sz;
static size_t sa_addr_offset;
static socklen_t sa_len;

static int batch_at;
static int numhosts = 10;
static int portpid;
static int stopper = MAXHOST;
enum { RE_PONG, RE_EXCEED, RE_UNREACH }; // reason of a pong response

bool addr4exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in_addr)) ? true : false; }
bool addr4equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in_addr)) ? false : true; }
void* addr4copy(void *dst, const void *src) { return memcpy(dst, src, sizeof(struct in_addr)); }
#ifdef ENABLE_IPV6
bool addr6exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in6_addr)) ? true : false; }
bool addr6equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in6_addr)) ? false : true; }
void* addr6copy(void *dst, const void *src) { return memcpy(dst, src, sizeof(struct in6_addr)); }
#endif

// return in 'tv' waittime before sending the next ping
void waitspec(struct timespec *tv) {
  double wait = wait_time;
  int n = numhosts;
  int f = fstTTL - 1;
  if ((f > 0) && (n > f))
    n -= f;
  wait /= n;
  tv->tv_sec = trunc(wait);
  tv->tv_nsec = (wait - tv->tv_sec) * NANO;
}

static uint16_t sum1616(const uint16_t *data, unsigned len, unsigned sum) {
  for (; len; len--)
    sum += *data++;
  while (sum >> 16)
    sum = (sum >> 16) + (sum & 0xffff);
  return ~sum;
}

// Prepend pseudoheader to the udp datagram and calculate checksum
static uint16_t udpsum16(struct _iphdr *ip, void *udata, int udata_len, int dsize) {
  unsigned tsize = sizeof(struct _udpph) + dsize;
  char csumpacket[tsize];
  memset(csumpacket, bitpattern, tsize);
  struct _udpph *prepend = (struct _udpph *)csumpacket;
  prepend->saddr = ip->saddr;
  prepend->daddr = ip->daddr;
  prepend->zero  = 0;
  prepend->proto = ip->proto;
  prepend->len   = udata_len;
  struct udphdr *content = (struct udphdr *)(csumpacket + sizeof(struct _udpph));
  struct udphdr *data = (struct udphdr *)udata;
  content->uh_sport = data->uh_sport;
  content->uh_dport = data->uh_dport;
  content->uh_ulen  = data->uh_ulen;
  content->uh_sum   = data->uh_sum;
  return sum1616((uint16_t*)csumpacket, tsize / 2, (tsize % 2) ? (bitpattern & 0xff) : 0);
}

static inline bool save_send_ts(int seq) {
  int rc = clock_gettime(CLOCK_MONOTONIC, &seqlist[seq].time);
  if (rc < 0) FAIL_CLOCK_GETTIME;
  return true;
}

static void save_sequence(int seq, int at) {
  LOGMSG_("seq=%d at=%d", seq, at);
  seqlist[seq].at = at;
  seqlist[seq].transit = true;
  if (host[at].transit)
    host[at].up = false; // if previous packet is in transit too, then assume it's down
  host[at].transit = true;
  host[at].sent++;
#ifdef CURSESMODE
  seqlist[seq].saved_seq = host[at].sent;
  if (host[at].saved[SAVED_PINGS - 1] != CT_UNSENT) {
    for (int at = 0; at < MAXHOST; at++) {
      memmove(host[at].saved, host[at].saved + 1, (SAVED_PINGS - 1) * sizeof(int));
      host[at].saved[SAVED_PINGS - 1] = CT_UNSENT;
      host[at].saved_seq_offset += 1;
    }
  }
  host[at].saved[SAVED_PINGS - 1] = CT_UNKN;
#endif
}

static int new_sequence(int at) {
  static int max_seqs[] = { [IPPROTO_ICMP] = MAXSEQ, [IPPROTO_UDP] = UDPPORTS };
  static int next_seq;
  int seq = next_seq++;
  if (next_seq >= max_seqs[mtrtype])
    next_seq = 0;
  save_sequence(seq, at);
  return seq;
}

static bool settosttl(int sock, int ttl) {
  if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0)
    FAIL_WITH_WARN(sock, "setsockopt(TTL=%d)", ttl);
#ifdef IP_TOS
  if (tos)
    if (setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0)
      FAIL_WITH_WARN(sock, "setsockopt(TOS=%d)", tos);
#endif
  return true;
}

#ifdef ENABLE_IPV6
static bool settosttl6(int sock, int ttl) {
  if (setsockopt(sendsock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) < 0)
    FAIL_WITH_WARN(sock, "setsockopt6(TTL=%d)", ttl);
#ifdef IPV6_TCLASS
  if (tos)
    if (setsockopt(sendsock, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0)
      FAIL_WITH_WARN(sock, "setsockopt6(TOS=%d)", tos);
#endif
  return true;
}
#endif

// Create TCP socket for hop 'at', and try to connect (poll results later)
static bool net_send_tcp(int at) {
#define SET_TCP_ATTR(src_addr, ssa_addr, dst_addr, dst_port) { \
  addr_copy(&src_addr, &ssa_addr); \
  addr_copy(&dst_addr, remote_ipaddr); \
  dst_port = htons((dst_port > 0) ? dst_port : TCP_DEFAULT_PORT); \
}
  int sock = socket(af, SOCK_STREAM, 0);
  if (sock < 0)
    FAIL_WITH_WARN(sock, "socket[at=%d]", at);
  /*summ*/ sum_sock[0]++;

  t_sockaddr local = {0}, remote = {0};
  local.SA_AF = remote.SA_AF = af;
  socklen_t addrlen = sizeof(local);
  switch (af) {
    case AF_INET:
      SET_TCP_ATTR(local.S_ADDR, lsa.S_ADDR, remote.S_ADDR, remote.S_PORT);
      addrlen = sizeof(lsa.sin);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      SET_TCP_ATTR(local.S6ADDR, lsa.S6ADDR, remote.S6ADDR, remote.S6PORT)
      addrlen = sizeof(lsa.sin6);
      break;
#endif
    default:
      FAIL_POSTPONE(ENOPROTOOPT, "address family %d", af);
  }
  if (bind(sock, &local.sa, addrlen))
    FAIL_WITH_WARN(sock, "bind[at=%d]", at);
  if (getsockname(sock, &local.sa, &addrlen))
    FAIL_WITH_WARN(sock, "getsockname[at=%d]", at);
  int flags = fcntl(sock, F_GETFL, 0);
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
    FAIL_WITH_WARN(sock, "fcntl(O_NONBLOCK) at=%d", at);

  int ttl = at + 1, port;
  switch (af) {
    case AF_INET:
      if (!settosttl(sock, ttl)) return false;
      port = ntohs(local.S_PORT);
    break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      if (!settosttl6(sock, ttl)) return false;
      port = ntohs(local.S6PORT);
    break;
#endif
    default:
      FAIL_POSTPONE(ENOPROTOOPT, "address family %d", af);
  }

  int seq = port % MAXSEQ;
  if (poll_reg_fd(sock, seq) < 0)
    FAIL_WITH_WARNX(1, sock, "no place in pool for sockets (at=%d)", at);
  save_sequence(seq, at);
  if (!save_send_ts(seq)) return false;
  connect(sock, &remote.sa, addrlen); // NOLINT(bugprone-unused-return-value)
#ifdef LOGMOD
  { struct timespec now;
    int rc = clock_gettime(CLOCK_MONOTONIC, &now); // LOGMOD for debug only
    LOGMSG_("at=%d seq=%d sock=%d: ttl=%d (ts=%lld.%09ld)", at, seq, sock, ttl, rc ? 0 : (long long)now.tv_sec, rc ? 0 : now.tv_nsec); }
#endif
  /*summ*/ net_queries[QR_SUM]++; net_queries[QR_TCP]++;
  return true;
#undef SET_TCP_ATTR
}

static inline void net_fill_icmp_hdr(uint16_t seq, uint8_t type, uint8_t *data, uint16_t size) {
  struct _icmphdr *icmp = (struct _icmphdr *)data;
  icmp->type = type;
  icmp->code = 0;
  icmp->sum  = 0;
  icmp->id   = mypid;
  icmp->seq  = seq;
  icmp->sum  = sum1616((uint16_t*)data, size / 2, (size % 2) ? (bitpattern & 0xff) : 0);
  LOGMSG_("icmp: seq=%d id=%u", icmp->seq, icmp->id);
}

static inline bool net_fill_udp_hdr(uint16_t seq, uint8_t *data, uint16_t size
#ifdef IP_HDRINCL
  , struct _iphdr *ip
#endif
) {
  struct udphdr *udp = (struct udphdr *)data;
  udp->uh_sum  = 0;
  udp->uh_ulen = htons(size);
  if (remoteport < 0)
    SET_UDP_UH_PORTS(udp, portpid, LO_UDPPORT + seq)
  else
    SET_UDP_UH_PORTS(udp, LO_UDPPORT + seq, remoteport);
  LOGMSG_("udp: seq=%d port=%u", seq, ntohs(udp->uh_dport));
  switch (af) {
    case AF_INET:
#ifdef IP_HDRINCL
      if (ip->saddr) { // checksum is not mandatory, calculate if source address is known
        uint16_t sum = udpsum16(ip, udp, udp->uh_ulen, size);
        udp->uh_sum = sum ? sum : 0xffff;
      }
#endif
      return true;
#ifdef ENABLE_IPV6
    case AF_INET6: { // checksumming by kernel
      int opt = 6;
      if (setsockopt(sendsock, IPPROTO_IPV6, IPV6_CHECKSUM, &opt, sizeof(opt)))
        FAIL_WITH_WARN(sendsock, "setsockopt6(CHECKSUM) optval=%d", opt);
    } return true;
#endif
  } return false;
}


// Send packet for hop 'at'
static bool net_send_icmp_udp(int at) {
  if (packetsize < MINPACKET) packetsize = MINPACKET;
  else if (packetsize > MAXPACKET) packetsize = MAXPACKET;
  static uint8_t packet[MAXPACKET];
  memset(packet, bitpattern, packetsize);

  int iphsize = 0, echotype = 0, salen = 0;
#ifdef IP_HDRINCL
  struct _iphdr *ip = (struct _iphdr *)packet;
#endif
  int ttl = at + 1;

  switch (af) {
    case AF_INET:
#ifdef IP_HDRINCL
      iphsize = sizeof(struct _iphdr);
      ip->ver   = 4;
      ip->ihl   = 5;
      ip->tos   = tos;
      ip->len   = IPLEN_RAW(packetsize);
      ip->id    = 0;
      ip->frag  = 0;
      ip->ttl   = ttl;
      ip->proto = mtrtype;
      ip->sum   = 0;
      // BSD needs the source IPv4 address here
      addr_copy(&ip->saddr, &lsa.S_ADDR);
      addr_copy(&ip->daddr, &rsa.S_ADDR);
#else
      if (!settosttl(sendsock, ttl)) return false;
      iphsize = 0;
#endif
      echotype = ICMP_ECHO;
      salen = sizeof(struct sockaddr_in);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      if (!settosttl6(sendsock, ttl)) return false;
      iphsize = 0;
      echotype = ICMP6_ECHO_REQUEST;
      salen = sizeof(struct sockaddr_in6);
      break;
#endif
    default:
      FAIL_POSTPONE(ENOPROTOOPT, "address family %d", af);
  }

  int seq = new_sequence(at);
  uint8_t *ipdata = packet + iphsize;
  uint16_t ipdatasize = packetsize - iphsize;
  switch (mtrtype) {
    case IPPROTO_ICMP:
      net_fill_icmp_hdr(seq, echotype, ipdata, ipdatasize);
      break;
    case IPPROTO_UDP:
      if (!net_fill_udp_hdr(seq, ipdata, ipdatasize
#ifdef IP_HDRINCL
         , ip
#endif
      )) return false;
      break;
    default:
      FAIL_POSTPONE(EPROTONOSUPPORT, "protocol type %d", mtrtype);
  }

  if (!save_send_ts(seq)) return false;
  if (sendto(sendsock, packet, packetsize, 0, &rsa.sa, salen) < 0) {
    int rc = errno; const char *dst = strlongip(remote_ipaddr); errno = rc;
    FAIL_WITH_WARN(sendsock, "sendto(%s)", dst ? dst : "");
  }
  /*summ*/ net_queries[QR_SUM]++; (mtrtype == IPPROTO_ICMP) ? net_queries[QR_ICMP]++ : net_queries[QR_UDP];
  return true;
}


static void stats(int at, timemsec_t curr) {
  double curr_f = msec2float(curr);
  LOGMSG_("prev=%lld.%09ld curr=%lld.%09ld", (long long)host[at].last.ms, host[at].last.frac, (long long)curr.ms, curr.frac);

  if (host[at].recv < 1) {
    host[at].best = host[at].worst = curr;
    host[at].mean = curr_f;
    host[at].var = host[at].jitter = host[at].jworst = host[at].jinta = host[at].avg = 0;
  } else {
    double jitter = float_sub_msec(curr, host[at].last);
    host[at].jitter = (jitter < 0) ? -jitter : jitter; // abs()
  }
  host[at].last = curr;

  if (mseccmp(curr, host[at].best, <))
     host[at].best = curr;
  if (mseccmp(curr, host[at].worst, >))
     host[at].worst = curr;
  if (host[at].jitter > host[at].jworst)
     host[at].jworst = host[at].jitter;

  host[at].recv++;
  double davg = curr_f - host[at].avg;
  host[at].avg += davg / host[at].recv;
  host[at].var += davg * (curr_f - host[at].avg);

  host[at].javg  += (host[at].jitter - host[at].javg)  / host[at].recv;
  host[at].jinta += (host[at].jitter - host[at].jinta) / 16; /* RFC1889 A.8 */

  if (host[at].recv > 1) {
    double inv_recv = 1 / (double)host[at].recv;
    host[at].mean = pow(host[at].mean, 1 - inv_recv) * pow(curr_f, inv_recv);
  }

  host[at].up = true;
  host[at].transit = false;
  if (cache_mode)
    host[at].seen = time(NULL);
}

static int addr2ndx(int hop, const t_ipaddr *addr) { // return index of 'addr' at 'hop', otherwise -1
  for (int i = 0; i < MAXPATH; i++)
    if (addr_equal(&IP_AT_NDX(hop, i), addr))
      return i;
  return -1;
}

int at2next(int hop) { // return first free slot at 'hop', otherwise -1
  for (int i = 0; i < MAXPATH; i++)
    if (!addr_exist(&IP_AT_NDX(hop, i)))
      return i;
  return -1;
}

// set new ip-addr and clear associated data
static void set_new_addr(int at, int ndx, const t_ipaddr *ipaddr MPLSFNTAIL(const mpls_data_t *mpls)) {
  addr_copy(&IP_AT_NDX(at, ndx), ipaddr);
#ifdef WITH_MPLS
  mpls ? memcpy(&MPLS_AT_NDX(at, ndx), mpls, sizeof(mpls_data_t))
    : memset(&MPLS_AT_NDX(at, ndx), 0, sizeof(mpls_data_t));
#endif
  if (QPTR_AT_NDX(at, ndx)) {
    free(QPTR_AT_NDX(at, ndx));
    QPTR_AT_NDX(at, ndx) = NULL;
  }
  if (RPTR_AT_NDX(at, ndx)) {
    free(RPTR_AT_NDX(at, ndx));
    RPTR_AT_NDX(at, ndx) = NULL;
  }
#ifdef WITH_IPINFO
  if (QTXT_AT_NDX(at, ndx)) {
    free(QTXT_AT_NDX(at, ndx));
    QTXT_AT_NDX(at, ndx) = NULL;
  }
  for (int i = 0; i < MAX_TXT_ITEMS; i++) {
    if (RTXT_AT_NDX(at, ndx, i)) {
      free(RTXT_AT_NDX(at, ndx, i));
      RTXT_AT_NDX(at, ndx, i) = NULL;
    }
  }
#endif
}


// Got a return
static int net_stat(unsigned port, const void *addr, struct timespec *recv_at, int reason MPLSFNTAIL(const mpls_data_t *mpls)) {
  unsigned seq = port % MAXSEQ;
  if (!seqlist[seq].transit)
    return true;
#ifdef WITH_MPLS
  LOGMSG_("at=%d seq=%d (labels=%d)", seqlist[seq].at, seq, mpls ? mpls->n : 0);
#else
  LOGMSG_("at=%d seq=%d", seqlist[seq].at, seq);
#endif
  seqlist[seq].transit = false;

  int at = seqlist[seq].at;
  if (reason == RE_UNREACH) {
    if (at < stopper)
      stopper = at;    // set stopper
  } else if (stopper == at)
    stopper = MAXHOST; // clear stopper

  if (at > stopper)    // return unless reachable
    return true;

  t_ipaddr copy;
  addr_copy(&copy, addr); // can it be overwritten?
  int ndx = addr2ndx(at, &copy);
  if (ndx < 0) {        // new one
    ndx = at2next(at);
    if (ndx < 0) {      // no free slots? warn about it, and change the last one
      WARNX_("MAXPATH=%d is exceeded at hop=%d", MAXPATH, at);
      ndx = MAXPATH - 1;
    }
    set_new_addr(at, ndx, &copy MPLSFNTAIL(mpls));
#ifdef OUTPUT_FORMAT_RAW
    if (enable_raw)
      raw_rawhost(at, &IP_AT_NDX(at, ndx));
#endif
  }
#ifdef WITH_MPLS
  else if (mpls && memcmp(&MPLS_AT_NDX(at, ndx), mpls, sizeof(mpls_data_t))) {
    LOGMSG_("update mpls at=%d ndx=%d (labels=%d)", at, ndx, mpls->n);
    memcpy(&MPLS_AT_NDX(at, ndx), mpls, sizeof(mpls_data_t));
  }
#endif

  struct timespec tv, stated_now;
  if (!recv_at) { // try again
    recv_at = &stated_now;
    if (clock_gettime(CLOCK_MONOTONIC, recv_at) < 0)
      FAIL_CLOCK_GETTIME;
  }
  timespecsub(recv_at, &seqlist[seq].time, &tv);
  timemsec_t curr = { .ms = time2msec(tv), .frac = time2mfrac(tv) };
  stats(at, curr);

#ifdef CURSESMODE
  int n = seqlist[seq].saved_seq - host[at].saved_seq_offset;
  if ((n >= 0) && (n <= SAVED_PINGS))
    host[at].saved[n] = time2usec(tv);
#endif
#ifdef OUTPUT_FORMAT_RAW
  if (enable_raw)
    raw_rawping(at, time2usec(tv));
#endif
  return true;
}

#ifdef WITH_MPLS
static inline bool mplslike(int psize, int hsize) { return enable_mpls & ((psize - hsize) >= MPLSMIN); }

static mpls_data_t *decodempls(const uint8_t *data, int sz) {
  static mpls_data_t mplsdata;
  // given: icmpext_struct(4) icmpext_object(4) label(4) [label(4) ...]
  static const size_t mplsoff = MPLSMIN - (IES_SZ + IEO_SZ + LAB_SZ);
  static const size_t ieomin = IEO_SZ + LAB_SZ;
  if (sz < MPLSMIN) {
    LOGMSG_("got %d bytes of data, whereas mpls min is %d", sz, MPLSMIN);
    return NULL;
  }
  int off = mplsoff; // at least 12bytes ahead: icmp_ext_struct(4) icmp_ext_object(4) label(4) [label(4) ...]
  // icmp extension structure
  struct icmpext_struct *ies = (struct icmpext_struct *)&data[off];
  if ((ies->ver != ICMP_EXT_VER) || ies->res || !ies->sum) {
    LOGMSG_("got ver=%d res=%d sum=%d, expected ver=%d res=0 sum!=0", ies->ver, ies->res, ies->sum, ICMP_EXT_VER);
    return NULL;
  }
  off += IES_SZ;
  // icmp extension object
  struct icmpext_object *ieo = (struct icmpext_object *)&data[off];
  ieo->len = ntohs(ieo->len);
  if ((ieo->len < ieomin) || (ieo->class != ICMP_EXT_CLASS_MPLS) || (ieo->type != ICMP_EXT_TYPE_MPLS)) {
    LOGMSG_("got len=%d class=%d type=%d, expected len>=%zd class=%d type=%d",
      ieo->len, ieo->class, ieo->type, ieomin, ICMP_EXT_CLASS_MPLS, ICMP_EXT_TYPE_MPLS);
    return NULL;
  }
  uint8_t n = (ieo->len - IEO_SZ) / LAB_SZ;
  off += IEO_SZ;
  // limit number of MPLS labels
  if (n > MAXLABELS) {
    LOGMSG_("got %d MPLS labels, limit=%d", n, MAXLABELS);
    n = MAXLABELS;
  }
  memset(&mplsdata, 0, sizeof(mplsdata));
  // mpls labels
  while ((mplsdata.n < n) && ((off + LAB_SZ) <= sz)) {
    mplsdata.label[mplsdata.n++].u32 = ntohl(*(uint32_t*)&data[off]);
    off += LAB_SZ;
  }
  return &mplsdata;
}
#endif


void net_icmp_parse(struct timespec *recv_at) {
#define ICMPSEQID { seq = icmp->seq; if (icmp->id != (uint16_t)mypid) \
  LOGRET_("icmp: unknown id=%u type=%d seq=%d", icmp->id, icmp->type, seq); }

  uint8_t packet[MAXPACKET];
  struct sockaddr_storage sa_in;

  ssize_t sz = recvfrom(recvsock, packet, MAXPACKET, 0, (struct sockaddr *)&sa_in, &sa_len);
  LOGMSG_("got %zd bytes", sz);
  if (sz < hdr_minsz)
    LOGRET_("incorrect packet size %zd [af=%d proto=%d minsize=%zd]", sz, af, mtrtype, hdr_minsz);

  struct _icmphdr *icmp = (struct _icmphdr *)(packet + iphdr_sz);
  uint8_t *data = ((uint8_t*)icmp) + ipicmphdr_sz;

#ifdef WITH_MPLS
  bool mplson = false;
#endif
  int seq = -1, reason = -1;
  switch (mtrtype) {
    case IPPROTO_ICMP: {
      if (icmp->type == echo_reply) {
        reason = RE_PONG;
        ICMPSEQID;
      } else if ((icmp->type == time_exceed) || (icmp->type == dst_unreach)) {
        if (sz < minfailsz)
          LOGRET_("incorrect packet size %zd [af=%d proto=%d expect>=%zd]", sz, af, mtrtype, minfailsz);
        reason = (icmp->type == time_exceed) ? RE_EXCEED : RE_UNREACH;
        icmp = (struct _icmphdr *)data;
        ICMPSEQID;
#ifdef WITH_MPLS
        mplson = mplslike(sz, data - packet);
#endif
      }
#ifdef WITH_MPLS
      LOGMSG_("icmp seq=%d type=%d mpls=%d", seq, icmp->type, mplson);
#else
      LOGMSG_("icmp seq=%d type=%d", seq, icmp->type);
#endif
      /*summ*/ net_replies[QR_ICMP]++;
    } break;

    case IPPROTO_UDP: {
      struct udphdr *uh = (struct udphdr *)data;
      if (remoteport < 0) {
        if (ntohs(uh->uh_sport) != portpid)
          return;
        seq = ntohs(uh->uh_dport);
      } else {
        if (ntohs(uh->uh_dport) != remoteport)
          return;
        seq = ntohs(uh->uh_sport);
      }
      seq -= LO_UDPPORT;
#ifdef WITH_MPLS
      mplson = mplslike(sz, data - packet);
      LOGMSG_("udp seq=%d id=%d mpls=%d", seq, portpid, mplson);
#else
      LOGMSG_("udp seq=%d id=%d", seq, portpid);
#endif
      /*summ*/ net_replies[QR_UDP]++;
    } break;

    case IPPROTO_TCP: {
      struct tcphdr *th = (struct tcphdr *)data;
      seq = ntohs(th->th_sport);
#ifdef WITH_MPLS
      mplson = mplslike(sz, data - packet);
      LOGMSG_("tcp seq=%d mpls=%d", seq, mplson);
#else
      LOGMSG_("tcp seq=%d", seq);
#endif
      /*summ*/ net_replies[QR_TCP]++;
    } break;
    default: LOGRET_("Unsupported proto %d", mtrtype);
  } /*end of switch(mtrtype)*/

  /*summ*/ net_replies[QR_SUM]++;

  if (seq >= 0) net_stat(seq, ((uint8_t*)&sa_in) + sa_addr_offset, recv_at,
    reason MPLSFNTAIL(mplson ? decodempls(data, sz - (data - packet)) : NULL));
#undef ICMPSEQID
}


const char *net_elem(int at, char c) {
  static char elemstr[16];
  int ival = -1;
  switch (c) {
    case 'D':  // Dropped Packets
      ival = host[at].sent - host[at].recv - (int)host[at].transit; break;
    case 'R':  // Received Packets
      ival = host[at].recv; break;
    case 'S':  // Sent Packets
      ival = host[at].sent; break;
  }
  if (ival >= 0) {
    snprintf(elemstr, sizeof(elemstr), "%d", ival);
    return elemstr;
  }
  double val;
  char *suffix = NULL;
  switch (c) {
    case 'N':   // Newest RTT(msec)
      val = msec2float(host[at].last); break;
    case 'B':   // Min/Best RTT(msec)
      val = msec2float(host[at].best); break;
    case 'A':   // Average RTT(msec)
      val = host[at].avg; break;
    case 'W':   // Max/Worst RTT(msec)
      val = msec2float(host[at].worst); break;
    case 'G':   // Geometric Mean
      val = host[at].mean; break;
    case 'L': { // Loss Ratio
      int known = host[at].sent - (int)host[at].transit; // transit ? 1 : 0;
      val = known ? (100 - (100.0 * host[at].recv / known)) : 0;
      suffix = "%";
      } break;
    case 'V': { // Standard Deviation
      int re = host[at].recv - 1;
      val = (re > 0) ? sqrt(host[at].var / re) : 0;
      } break;
    case 'J':   // Current Jitter
      val = host[at].jitter; break;
    case 'M':   // Jitter Mean/Avg
      val = host[at].javg; break;
    case 'X':   // Worst Jitter
      val = host[at].jworst; break;
    case 'I':   // Interarrival Jitter
      val = host[at].jinta; break;
    default: return NULL;
  }
  snprintf(elemstr, sizeof(elemstr), "%.*f%s", val2len(val), val, suffix ? suffix : "");
  return elemstr;
}

int net_max(void) {
  int max = 0;
  for (int at = 0; at < maxTTL; at++) {
    if (addr_equal(&CURRENT_IP(at), remote_ipaddr)) {
      max = at + 1;
      if (endpoint_mode)
        fstTTL = max;
      break;
    } else if (addr_exist(&CURRENT_IP(at))) {
      max = at + 2;
      if (endpoint_mode)
        fstTTL = max - 1; // -1: show previous known hop
    }
  }
  if (max > maxTTL)
    max = maxTTL;
  return max;
}

inline int net_min(void) { return (fstTTL - 1); }

inline void net_end_transit(void) { for (int at = 0; at < MAXHOST; at++) host[at].transit = false; }

int net_send_batch(void) {
  if (batch_at < fstTTL) {
    // Randomize bit-pattern and packet-size if requested
    bitpattern = (cbitpattern < 0) ? RANDUNIFORM(256) : cbitpattern;
    if (cpacketsize < 0) {
      int base = -cpacketsize - MINPACKET;
      packetsize = base ? (MINPACKET + RANDUNIFORM(base)) : MINPACKET;
    } else
      packetsize = cpacketsize;
  }

  { // Send packet if needed
    bool ping = true;
    if (cache_mode)
      if (host[batch_at].up && (host[batch_at].seen > 0))
        if ((time(NULL) - host[batch_at].seen) <= cache_timeout)
          ping = false;
    if (ping && !( (mtrtype == IPPROTO_TCP) ?
        net_send_tcp(batch_at) : net_send_icmp_udp(batch_at) ))
      LOG_RE(-1, "failed");
  }

  { // Calculate rc for caller
    int n_unknown = 0;
    for (int at = fstTTL - 1; at < batch_at; at++) {
      if (!addr_exist(&CURRENT_IP(at)))
        n_unknown++;
      if (addr_equal(&CURRENT_IP(at), remote_ipaddr))
        n_unknown = MAXHOST; // Make sure we drop into "we should restart"
    }
    if (addr_equal(&CURRENT_IP(batch_at), remote_ipaddr) // success in reaching target
        || (n_unknown > MAX_UNKNOWN_HOSTS) // fail in consecuitive MAX_UNKNOWN_HOSTS
        || (batch_at >= (maxTTL - 1))      // or reach limit
        || (batch_at >= stopper)) {        // or learnt unreachable
      numhosts = batch_at + 1;
      batch_at = fstTTL - 1;
      LOGMSG_("stop at hop #%d", numhosts);
      return 1;
    }
  }

  batch_at++;
  return 0;
}

static void net_sock_close(void) {
  CLOSE(sendsock4);
  CLOSE(recvsock4);
#ifdef ENABLE_IPV6
  CLOSE(sendsock6_icmp);
//  CLOSE(sendsock6_udp);
//  CLOSE(sendsock6_tcp);
  CLOSE(recvsock6);
#endif
}

#ifdef LIBCAP
#include <sys/capability.h>
void set_rawcap_flag(cap_flag_value_t flag) {
  static const cap_value_t cap_net_raw = CAP_NET_RAW;
  cap_t proc = cap_get_proc();
  if (proc) {
    cap_flag_value_t perm = flag;
    cap_get_flag(proc, cap_net_raw, CAP_PERMITTED, &perm);
    if (perm == flag) {
      if (cap_set_flag(proc, CAP_EFFECTIVE, 1, &cap_net_raw, flag) < 0) WARN("cap_set_flag");
      else if (cap_set_proc(proc) < 0) WARN("cap_set_proc");
    }
    cap_free(proc);
  } else WARN("cap_get_proc");
}
#define RAWCAP_ON  set_rawcap_flag(CAP_SET)
#define RAWCAP_OFF set_rawcap_flag(CAP_CLEAR)
#else
#define RAWCAP_ON
#define RAWCAP_OFF
#endif

static int net_socket(int domain, int type, int proto, const char *what) {
  RAWCAP_ON;
  int sock = socket(domain, type, proto);
  if (sock < 0) warn("%s: %s", __func__, what); else /*summ*/ sum_sock[0]++;
  RAWCAP_OFF;
  if (sock < 0) net_sock_close();
  return sock;
}

bool net_open(void) {
  // mandatory ipv4
  RAWCAP_ON;
  sendsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  RAWCAP_OFF;
  if (sendsock4 < 0) // backup
    if ((sendsock4 = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP, "send socket")) < 0)
      return false;
  if ((recvsock4 = net_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP, "recv socket")) < 0)
    return false;
#ifdef ENABLE_IPV6
  // optional ipv6: to not fail
  RAWCAP_ON;
  recvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  sendsock6_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
//  sendsock6_udp = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
//  sendsock6_tcp = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
  RAWCAP_OFF;
#endif
#ifdef IP_HDRINCL
  int trueopt = 1; // tell that we provide IP header
  if (setsockopt(sendsock4, 0, IP_HDRINCL, &trueopt, sizeof(trueopt)) < 0) {
    WARN("setsockopt(IP_HDRINCL)");
    net_sock_close();
    return false;
  }
#endif
  return true;
}

#ifdef ENABLE_IPV6
inline void net_setsocket6(void) {
  if (mtrtype == IPPROTO_ICMP) sendsock6 = sendsock6_icmp;
  else if (mtrtype == IPPROTO_UDP) { sendsock6 = /*sendsock6_udp*/-1; WARNX("UDP6 is not tested yet"); }
  else if (mtrtype == IPPROTO_TCP) { sendsock6 = /*sendsock6_tcp*/-1; WARNX("TCP6 is not tested yet"); }
}
#endif

bool net_set_host(t_ipaddr *ipaddr) {
  rsa.SA_AF = af;
  switch (af) {
    case AF_INET:
      sendsock = sendsock4;
      recvsock = recvsock4;
      addr_copy(&rsa.S_ADDR, ipaddr);
      remote_ipaddr = (t_ipaddr*)&rsa.S_ADDR;
    break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      if ((sendsock6 < 0) || (recvsock6 < 0)) {
        WARNX("No IPv6 sockets");
        return false;
      }
      sendsock = sendsock6;
      recvsock = recvsock6;
      addr_copy(&rsa.S6ADDR, ipaddr);
      remote_ipaddr = (t_ipaddr*)&rsa.S6ADDR;
    break;
#endif
  }

  if (!af || !addr_exist(remote_ipaddr)) {
    WARNX_("Unspecified destination (af=%d)", af);
    return false;
  }

  net_reset();
  { struct sockaddr_storage ss[1];
    socklen_t len = sizeof(*ss);
    if (!getsockname(recvsock, (struct sockaddr *)ss, &len)) {
      if (len > sizeof(*ss)) WARNX("Address of recv socket is truncated");
      int saf = ss->ss_family;
      char *addr =
#ifdef ENABLE_IPV6
        (saf == AF_INET6) ? (char*)&((struct sockaddr_in6 *)ss)->sin6_addr :
#endif
        ((saf == AF_INET) ? (char*)&((struct sockaddr_in *)ss)->sin_addr : NULL);
      if (!addr) WARNX_("Unknown address family: %d", saf);
      else if (!inet_ntop(saf, addr, localaddr, sizeof(localaddr))) WARN("inet_ntop()");
    } else WARN("getsockname()");
  }
  portpid = IPPORT_RESERVED + mypid % (65535 - IPPORT_RESERVED);
  return true;
}

void net_reset(void) {
  for (int at = 0; at < MAXHOST; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      set_new_addr(at, ndx, &unspec_addr MPLSFNTAIL(NULL));  // clear all query-response cache
  memset(host, 0, sizeof(host));
#ifdef CURSESMODE
  for (int at = 0; at < MAXHOST; at++) {
    for (int i = 0; i < SAVED_PINGS; i++)
      host[at].saved[i] = CT_UNSENT; // unsent
    host[at].saved_seq_offset = -SAVED_PINGS + 2;
  }
#endif
  poll_close_tcpfds();
  for (int i = 0; i < MAXSEQ; i++)
    seqlist[i].transit = false;
  batch_at = fstTTL - 1;
  stopper = MAXHOST;
  numhosts = 10;
}


bool net_set_ifaddr(const char *ifaddr) {
  int len = 0;
  lsa.SA_AF = af;
  switch (af) {
    case AF_INET:
      lsa.S_PORT = 0;
      if (!inet_aton(ifaddr, &lsa.S_ADDR)) {
        WARNX_("bad address %s", ifaddr);
        return false;
      }
      len = sizeof(lsa.sin);
    break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      lsa.S6PORT = 0;
      if (inet_pton(af, ifaddr, &lsa.S6ADDR) < 1) {
        WARNX_("bad IPv6 address %s", ifaddr);
        return false;
      }
      len = sizeof(lsa.sin6);
    break;
#endif
  }
  if (bind(sendsock, &lsa.sa, len) < 0) {
    WARN_("bind(%d)", sendsock);
    return false;
  }
  return true;
}

void net_close(void) {
  net_sock_close();
  // clear memory allocated for query-response cache
  for (int at = 0; at < MAXHOST; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      set_new_addr(at, ndx, &unspec_addr MPLSFNTAIL(NULL));
}

inline int net_wait(void) { return recvsock; }

static int err_slippage(int sock) {
  socklen_t namelen = sizeof(rsa);
  int r = getpeername(sock, &rsa.sa, &namelen);
  if ((r < 0) && (errno == ENOTCONN)) {
    r = read(sock, &namelen, 1);
    if (r >= 0) return -1; // sanity lost
    r = errno;
  } else r = 0;
  return r;
}

// Check connection state with error-slippage
void net_tcp_parse(int sock, int seq, int noerr, struct timespec *recv_at) {
  int reason = -1, e = err_slippage(sock);
  LOGMSG_("recv <e=%d> sock=%d ts=%lld.%09ld", e, sock,
    recv_at ? (long long)(recv_at->tv_sec) : 0, recv_at ? recv_at->tv_nsec : 0);
  // if no errors, or connection refused, or host down, the target is probably reached
  switch (e) {
    case EHOSTUNREACH:
    case ENETUNREACH:
      reason = RE_UNREACH;
    case EHOSTDOWN:
    case ECONNREFUSED:
    case 0: // no error
      net_stat(seq, remote_ipaddr, recv_at, reason MPLSFNTAIL(NULL)); /*no MPLS decoding?*/
      LOGMSG_("stat seq=%d for sock=%d", seq, sock);
      break;
//  case EAGAIN: // need to wait more
  }
  seqlist[seq].transit = false;
  if (noerr) { /*summ*/ net_replies[QR_SUM]++; net_replies[QR_TCP]++; }
}

// Clean timed out TCP connection
bool net_timedout(int seq) {
  struct timespec now, dt;
  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
    FAIL_CLOCK_GETTIME;
  timespecsub(&now, &seqlist[seq].time, &dt);
  if (time2msec(dt) <= syn_timeout)
    return false;
  LOGMSG_("clean tcp seq=%d after %d sec", seq, syn_timeout / MIL);
  seqlist[seq].transit = false;
  return true;
}

#ifdef ENABLE_DNS
static void save_ptr_answer(int at, int ndx, const char* answer) {
  if (RPTR_AT_NDX(at, ndx)) {
    LOGMSG_("T_PTR dup or update at=%d ndx=%d for %s", at, ndx, strlongip(&IP_AT_NDX(at, ndx)));
    free(RPTR_AT_NDX(at, ndx));
    RPTR_AT_NDX(at, ndx) = NULL;
  }
  RPTR_AT_NDX(at, ndx) = strnlen(answer, NAMELEN) ? strndup(answer, NAMELEN) :
    // if no answer, save ip-address in text representation
    strndup(strlongip(&IP_AT_NDX(at, ndx)), NAMELEN);
  if (!RPTR_AT_NDX(at, ndx))
    WARN_("[%d:%d] strndup()", at, ndx);
}
#endif

void net_assert(void) { // to be sure
  assert(sizeof(struct _iphdr)   == 20);
  assert(sizeof(struct _udpph)   == 12);
  assert(sizeof(struct _icmphdr) == 8);
#ifdef WITH_MPLS
  assert(IES_SZ == 4);
  assert(IEO_SZ == 4);
  assert(LAB_SZ == 4);
#endif
  net_settings(
#ifdef ENABLE_IPV6
    IPV6_DISABLED
#endif
  );
}

void net_set_type(int type) {
  LOGMSG_("proto type: %d", type);
  mtrtype = type;
  ipicmphdr_sz = iphdr_sz + sizeof(struct _icmphdr);
  hdr_minsz = iphdr_sz;
  switch (type) {
    case IPPROTO_ICMP: hdr_minsz += sizeof(struct _icmphdr); break;
    case IPPROTO_UDP:  hdr_minsz += sizeof(struct udphdr);   break;
    case IPPROTO_TCP:  hdr_minsz += sizeof(struct tcphdr);   break;
    default: WARN_("Unknown proto: %d", type);
  }
  minfailsz = hdr_minsz + ipicmphdr_sz;
}

#define NET46SETS(n_sz, n_er, n_te, n_un) { \
  sa_len = n_sz; \
  echo_reply  = n_er; \
  time_exceed = n_te; \
  dst_unreach = n_un; \
}

void net_settings(
#ifdef ENABLE_IPV6
  bool ipv6_enabled
#else
  void
#endif
) {
#ifdef ENABLE_DNS
  dns_ptr_handler = save_ptr_answer; // no checks, handler for net-module only
#endif
#ifdef ENABLE_IPV6
  if (ipv6_enabled) {
    af = AF_INET6;
    addr_exist = addr6exist;
    addr_equal = addr6equal;
    addr_copy  = addr6copy;
    iphdr_sz = 0;
    sa_addr_offset = offsetof(struct sockaddr_in6, sin6_addr);
    NET46SETS(sizeof(struct sockaddr_in6), ICMP6_ECHO_REPLY, ICMP6_TIME_EXCEEDED, ICMP6_DST_UNREACH);
  } else
#endif
  { // IPv4 by default
    af = AF_INET;
    addr_exist = addr4exist;
    addr_equal = addr4equal;
    addr_copy  = addr4copy;
    iphdr_sz = sizeof(struct _iphdr);
    sa_addr_offset = offsetof(struct sockaddr_in, sin_addr);
    NET46SETS(sizeof(struct sockaddr_in), ICMP_ECHOREPLY, ICMP_TIME_EXCEEDED, ICMP_UNREACH);
  }
  net_set_type(mtrtype);
}

const char *strlongip(t_ipaddr *ipaddr) {
  static char addrstr[MAX_ADDRSTRLEN];
  return inet_ntop(af, ipaddr, addrstr, sizeof(addrstr));
}

#ifdef WITH_MPLS
const char *mpls2str(const mpls_label_t *label, int indent) {
  static const char mpls_fmt[] = "%*s[Lbl:%u Exp:%u S:%u TTL:%u]";
  static char m2s_buf[64];
  snprintf(m2s_buf, sizeof(m2s_buf), mpls_fmt, indent, "", label->lab, label->exp, label->bos, label->ttl);
  return m2s_buf;
}
#endif

// type must correspond 'id' in resolve HEADER (unsigned id:16)
// it's used as a hint for fast search, 16bits as [hash:7 at:6 ndx:3]
uint16_t str2hint(const char* s, uint16_t at, uint16_t ndx) {
  uint16_t h = 0, c;
  while ((c = *s++))
    h = ((h << 5) + h) ^ c; // h * 33 ^ c
  h &= IDMASK;
  h |= AT2ID(at);
  h |= ID2NDX(ndx);
  return h;
}

