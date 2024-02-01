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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>

#include "net.h"
#include "aux.h"
#include "mtr-poll.h"
#include "display.h"
#include "report.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif

#ifdef HAVE_ARC4RANDOM_UNIFORM
#ifdef ARC4_IN_BSD_STDLIB_H
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

// udp4 pseudoheader
struct PACKIT udp_ph {
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

static const int ies_sz = sizeof(struct icmpext_struct);
static const int ieo_sz = sizeof(struct icmpext_object);
static const int lab_sz = sizeof(mpls_label_t);
static const int mplsmin = 120; // min after: [ip] icmp ip

#define MPLSFNTAIL(arg) , arg
#else
#define MPLSFNTAIL(arg)
#endif /*MPLS*/


#define LO_UDPPORT 33433	// start from LO_UDPPORT+1
#define UDPPORTS 90		// go thru udp:33434-33523 acl
#define TCP_DEFAULT_PORT 80

#define SET_UDP_UH_PORTS(uh, s, d) { (uh)->uh_sport = htons(s); (uh)->uh_dport = htons(d); }

// NOTE: don't forget to include sys/param.h
#ifdef __FreeBSD_version
#if __FreeBSD_version >= 1100000
#define IPLEN_RAW(sz) htons(sz)
#endif
#elif __OpenBSD__
#define IPLEN_RAW(sz) htons(sz)
#elif __HAIKU__
#define IPLEN_RAW(sz) htons(sz)
#ifndef IPV6_CHECKSUM
#define IPV6_CHECKSUM 7
#endif
#else
#define IPLEN_RAW(sz) sz
#endif

#define EXIT(s) { int e = errno; display_close(true); ERRX_(e, "%s: %s", s, strerror(e)); }

#define SET_TCP_ATTR(lo_addr, ssa_addr, re_addr, re_port, paddr) { \
  addr_copy(&lo_addr, &ssa_addr); \
  addr_copy(&re_addr, remoteaddress); \
  re_port = htons((remoteport > 0) ? remoteport : TCP_DEFAULT_PORT); \
  addrlen = sizeof(*paddr); \
}

#define CLOSE(fd) if ((fd) >= 0) { close(fd); fd = -1; /*summ*/ sum_sock[1]++; }

#define WARNRE0(fd, fmt, ...) { last_neterr = errno; display_clear(); CLOSE(fd); \
  WARNX_(fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
  snprintf(neterr_txt, ERRBYFN_SZ, fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
  LOG_RE_(false, fmt ": %s", __VA_ARGS__, strerror(last_neterr)); \
}

struct sequence {
  int at;
  bool transit;
  struct timespec time;
#ifdef CURSESMODE
  int saved_seq;
#endif
};

// global vars
ip_t unspec_addr;	// zero by definition
bool (*addr_exist)(const void *); // true if address is specified
bool (*addr_equal)(const void *, const void *); // equal
void* (*addr_copy)(void *, const void *);
int af;	// address family
struct nethost host[MAXHOST];
char localaddr[INET6_ADDRSTRLEN];
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
static struct timespec reset;

static int sendsock4 = -1;
static int recvsock4 = -1;
#ifdef ENABLE_IPV6
static int sendsock6 = -1;
static int sendsock6_icmp = -1;
static int sendsock6_udp = -1;
static int recvsock6 = -1;
#endif
static int sendsock = -1;
static int recvsock = -1;

#ifdef ENABLE_IPV6
static struct sockaddr_storage sourcesockaddr_struct;
static struct sockaddr_storage remotesockaddr_struct;
static struct sockaddr_in6 *ssa6 = (struct sockaddr_in6 *) &sourcesockaddr_struct;
static struct sockaddr_in6 *rsa6 = (struct sockaddr_in6 *) &remotesockaddr_struct;
#else
static struct sockaddr_in sourcesockaddr_struct;
static struct sockaddr_in remotesockaddr_struct;
#endif

static struct sockaddr *sourcesockaddr = (struct sockaddr *) &sourcesockaddr_struct;
static struct sockaddr *remotesockaddr = (struct sockaddr *) &remotesockaddr_struct;
static struct sockaddr_in *ssa4 = (struct sockaddr_in *) &sourcesockaddr_struct;
static struct sockaddr_in *rsa4 = (struct sockaddr_in *) &remotesockaddr_struct;

static ip_t *sourceaddress;
static ip_t *remoteaddress;

static int batch_at;
static int numhosts = 10;
static int portpid;
static int stopper = MAXHOST;
enum { RE_PONG, RE_EXCEED, RE_UNREACH }; // reason of a pong response


bool addr4exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in_addr)) ? true : false; }
bool addr4equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in_addr)) ? false : true; }
void* addr4copy(void *a, const void *b) { return memcpy(a, b, sizeof(struct in_addr)); }
#ifdef ENABLE_IPV6
bool addr6exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in6_addr)) ? true : false; }
bool addr6equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in6_addr)) ? false : true; }
void* addr6copy(void *a, const void *b) { return memcpy(a, b, sizeof(struct in6_addr)); }
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

static uint16_t sum16(const void *data, int sz) {
  const uint16_t *ch = data;
  unsigned sum = 0;
  for (; sz > 1; sz -= 2)
    sum += *ch++;
  if (sz)
    sum += *(uint8_t*)ch;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

// Prepend pseudoheader to the udp datagram and calculate checksum
static uint16_t udpsum16(struct _iphdr *ip, void *udata, int udata_len, int dsize) {
  unsigned tsize = sizeof(struct udp_ph) + dsize;
  char csumpacket[tsize];
  memset(csumpacket, bitpattern, tsize);
  struct udp_ph *prepend = (struct udp_ph *)csumpacket;
  prepend->saddr = ip->saddr;
  prepend->daddr = ip->daddr;
  prepend->zero  = 0;
  prepend->proto = ip->proto;
  prepend->len   = udata_len;
  struct udphdr *content = (struct udphdr *)(csumpacket + sizeof(struct udp_ph));
  struct udphdr *data = (struct udphdr *)udata;
  content->uh_sport = data->uh_sport;
  content->uh_dport = data->uh_dport;
  content->uh_ulen  = data->uh_ulen;
  content->uh_sum   = data->uh_sum;
  return sum16(csumpacket, tsize);
}


static void save_sequence(int seq, int at) {
  LOGMSG_("seq=%d at=%d", seq, at);
  seqlist[seq].at = at;
  seqlist[seq].transit = true;
  clock_gettime(CLOCK_MONOTONIC, &seqlist[seq].time);

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

static inline bool settosttl(int sock, int ttl) {
#ifdef IP_TTL
  if (setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)))
    WARNRE0(sock, "setsockopt(TTL=%d)", ttl);
#endif
#ifdef IP_TOS
  if (setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)))
    WARNRE0(sock, "setsockopt(TOS=%d)", tos);
#endif
  return true;
}

// Create TCP socket for hop 'at', and try to connect (poll results later)
static bool net_send_tcp(int at) {
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
#endif

  int ttl = at + 1;
  int sock = socket(af, SOCK_STREAM, 0);
  if (sock < 0)
    WARNRE0(sock, "socket[at=%d]", at);
  /*summ*/ sum_sock[0]++;

  memset(&local, 0, sizeof (local));
  memset(&remote, 0, sizeof (remote));
  local.ss_family = af;
  remote.ss_family = af;

  socklen_t addrlen;
#ifdef ENABLE_IPV6
  if (af == AF_INET6) SET_TCP_ATTR(local6->sin6_addr, ssa6->sin6_addr, remote6->sin6_addr, remote6->sin6_port, local6) else
#endif
  SET_TCP_ATTR(local4->sin_addr, ssa4->sin_addr, remote4->sin_addr, remote4->sin_port, local4);
  if (bind(sock, (struct sockaddr *) &local, addrlen))
    WARNRE0(sock, "bind[at=%d]", at);

  if (getsockname(sock, (struct sockaddr *) &local, &addrlen))
    WARNRE0(sock, "getsockname[at=%d]", at);

  int flags = fcntl(sock, F_GETFL, 0);
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
    WARNRE0(sock, "fcntl(O_NONBLOCK) at=%d", at);

  int port;
#ifdef ENABLE_IPV6
  if (af == AF_INET6) {
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)))
      WARNRE0(sock, "setsockopt6(TTL) at=%d", at);
    port = ntohs(local6->sin6_port);
  } else
#endif
  {
    settosttl(sock, ttl);
    port = ntohs(local4->sin_port);
  }

  int seq = port % MAXSEQ;
  if (poll_reg_fd(sock, seq) < 0)
    WARNRE0(sock, "no place in pool for sockets (at=%d)", at);
  save_sequence(seq, at);
  connect(sock, (struct sockaddr *) &remote, addrlen); // NOLINT(bugprone-unused-return-value)
#ifdef LOGMOD
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  LOGMSG_("at=%d seq=%d sock=%d: ttl=%d (ts=%lld.%09ld)", at, seq, sock, ttl, (long long)now.tv_sec, now.tv_nsec);
#endif
  /*summ*/ net_queries[QR_SUM]++; net_queries[QR_TCP]++;
  return true;
}

// Send packet for hop 'at'
static bool net_send(int at) {
  static char packet[MAXPACKET];
  if (mtrtype == IPPROTO_TCP)
    return net_send_tcp(at);

  if (packetsize < MINPACKET) packetsize = MINPACKET;
  else if (packetsize > MAXPACKET) packetsize = MAXPACKET;
  memset(packet, bitpattern, packetsize);

  int iphsize = 0, echotype = 0, salen = 0;
  struct _iphdr *ip = (struct _iphdr *)packet;
  int ttl = at + 1;

  switch (af) {
  case AF_INET:
#ifndef IP_HDRINCL
    iphsize = 0;
    settosttl(sendsock, ttl);
#else
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
    // BSD needs the source address here
    addr_copy(&(ip->saddr), &(ssa4->sin_addr));
    addr_copy(&(ip->daddr), remoteaddress);
#endif
    echotype = ICMP_ECHO;
    salen = sizeof(struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    iphsize = 0;
    if (setsockopt(sendsock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof ttl))
      WARNRE0(sendsock, "setsockopt6(TTL) at=%d", at);
    echotype = ICMP6_ECHO_REQUEST;
    salen = sizeof(struct sockaddr_in6);
    break;
#endif
  }

  if (mtrtype == IPPROTO_ICMP) {
    struct _icmphdr *icmp = (struct _icmphdr *)(packet + iphsize);
    icmp->type = echotype;
    icmp->code = 0;
    icmp->sum  = 0;
    icmp->id   = mypid;
    icmp->seq  = new_sequence(at);
    icmp->sum  = sum16(icmp, packetsize - iphsize);
    LOGMSG_("icmp: at=%d seq=%d id=%u", at, icmp->seq, icmp->id);
  } else if (mtrtype == IPPROTO_UDP) {
    struct udphdr *udp = (struct udphdr *)(packet + iphsize);
    udp->uh_sum  = 0;
    udp->uh_ulen = htons(packetsize - iphsize);
    int seq = new_sequence(at);
    if (remoteport < 0)
      SET_UDP_UH_PORTS(udp, portpid, LO_UDPPORT + seq)
    else
      SET_UDP_UH_PORTS(udp, LO_UDPPORT + seq, remoteport);
    LOGMSG_("udp: at=%d seq=%d port=%u", at, seq, ntohs(udp->uh_dport));
    if ((af == AF_INET) && ip->saddr) { // checksum is not mandatory, calculate if ip->saddr is known
      uint16_t sum = udpsum16(ip, udp, udp->uh_ulen, packetsize - iphsize);
      udp->uh_sum = sum ? sum : 0xffff;
    }
#ifdef ENABLE_IPV6
    else if (af == AF_INET6) { // kernel checksum calculation
      int offset = 6;
      if (setsockopt(sendsock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)))
        WARNRE0(sendsock, "setsockopt6(CHECKSUM) at=%d", at);
    }
#endif
  }

  if (sendto(sendsock, packet, packetsize, 0, remotesockaddr, salen) < 0)
    WARNRE0(sendsock, "sendto at=%d: ttl=%d", at, ttl);
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

int addr2ndx(int hop, ip_t *addr) { // return index of 'addr' at 'hop', otherwise -1
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

// Set new ip-addr and clear associated data
void set_new_addr(int at, int ndx, const ip_t *ip MPLSFNTAIL(const mpls_data_t *mpls)) {
  addr_copy(&IP_AT_NDX(at, ndx), ip);
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
static void net_stat(unsigned port, const void *addr, struct timespec now, int reason MPLSFNTAIL(const mpls_data_t *mpls)) {
  unsigned seq = port % MAXSEQ;
  if (!seqlist[seq].transit)
    return;
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
    return;

  ip_t copy;
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

  struct timespec tv;
  timespecsub(&now, &seqlist[seq].time, &tv);
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
}

static inline int proto_hdrsz(int type) {
  if (type == IPPROTO_ICMP) return sizeof(struct _icmphdr);
  if (type == IPPROTO_UDP)  return sizeof(struct udphdr);
  if (type == IPPROTO_UDP)  return sizeof(struct tcphdr);
  return 0;
}

#ifdef WITH_MPLS
static mpls_data_t *decodempls(const uint8_t *data, int sz) {
  static mpls_data_t mplsdata;
// given: icmpext_struct(4) icmpext_object(4) label(4) [label(4) ...]
  static const int mplsoff = mplsmin - (ies_sz + ieo_sz + lab_sz);
  if (sz < mplsmin) {
    LOGMSG_("got %d bytes of data, whereas mplsmin = %d", sz, mplsmin);
    return NULL;
  }
  int off = mplsoff; // at least 12bytes ahead: icmp_ext_struct(4) icmp_ext_object(4) label(4) [label(4) ...]
  // icmp extension structure
  struct icmpext_struct *ies = (struct icmpext_struct *)&data[off];
  if ((ies->ver != ICMP_EXT_VER) || ies->res || !ies->sum) {
    LOGMSG_("got ver=%d res=%d sum=%d, expected ver=%d res=0 sum!=0", ies->ver, ies->res, ies->sum, ICMP_EXT_VER);
    return NULL;
  }
  off += ies_sz;
  // icmp extension object
  struct icmpext_object *ieo = (struct icmpext_object *)&data[off];
  ieo->len = ntohs(ieo->len);
  if ((ieo->len < (ieo_sz + lab_sz)) || (ieo->class != ICMP_EXT_CLASS_MPLS) || (ieo->type != ICMP_EXT_TYPE_MPLS)) {
    LOGMSG_("got len=%d class=%d type=%d, expected len>=%d class=%d type=%d",
      ieo->len, ieo->class, ieo->type, ieo_sz + lab_sz, ICMP_EXT_CLASS_MPLS, ICMP_EXT_TYPE_MPLS);
    return NULL;
  }
  uint8_t n = (ieo->len - ieo_sz) / lab_sz;
  off += ieo_sz;
  // limit number of MPLS labels
  if (n > MAXLABELS) {
    LOGMSG_("got %d MPLS labels, limit=%d", n, MAXLABELS);
    n = MAXLABELS;
  }
  memset(&mplsdata, 0, sizeof(mplsdata));
  // mpls labels
  while ((mplsdata.n < n) && ((off + lab_sz) <= sz)) {
    mplsdata.label[mplsdata.n++].u32 = ntohl(*(uint32_t*)&data[off]);
    off += lab_sz;
  }
  return &mplsdata;
}
#endif

#define NET46SETS(sz, addr, er, te, un) { \
  fromsockaddrsize = sz; \
  fromaddress = (ip_t *) &(addr); \
  echoreplytype = er; \
  timeexceededtype = te; \
  unreachabletype = un; \
}

#define ICMPSEQID { seq = icmp->seq; if (icmp->id != (uint16_t)mypid) \
  LOGRET_("icmp: unknown id=%u type=%d seq=%d", icmp->id, icmp->type, seq); \
}

static int offsets(uint8_t *packet, int iph, uint8_t **icmp, uint8_t **data, int *failre) {
  int minre = iph + proto_hdrsz(mtrtype), ipicmphdr = iph + sizeof(struct _icmphdr);
  *icmp = packet + iph;
  *data = *icmp + ipicmphdr;
  *failre = minre + ipicmphdr;
  return minre;
}

#ifdef WITH_MPLS
static inline bool mplslike(int psize, int hsize) { return enable_mpls & ((psize - hsize) >= mplsmin); }
#endif

void net_icmp_parse(void) {
  uint8_t packet[MAXPACKET];
#ifdef ENABLE_IPV6
  struct sockaddr_storage fromsockaddr_struct;
  struct sockaddr_in6 *fsa6 = (struct sockaddr_in6 *) &fromsockaddr_struct;
#else
  struct sockaddr_in fromsockaddr_struct;
#endif
  struct sockaddr *fromsockaddr = (struct sockaddr *) &fromsockaddr_struct;
  struct sockaddr_in *fsa4 = (struct sockaddr_in *) &fromsockaddr_struct;
  socklen_t fromsockaddrsize;
  ip_t *fromaddress = NULL;
  int echoreplytype = 0, timeexceededtype = 0, unreachabletype = 0;

  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
#ifdef ENABLE_IPV6
  if (af == AF_INET6) NET46SETS(sizeof(struct sockaddr_in6), fsa6->sin6_addr, ICMP6_ECHO_REPLY, ICMP6_TIME_EXCEEDED, ICMP6_DST_UNREACH) else
#endif
  NET46SETS(sizeof(struct sockaddr_in), fsa4->sin_addr, ICMP_ECHOREPLY, ICMP_TIME_EXCEEDED, ICMP_UNREACH);

  ssize_t sz = recvfrom(recvsock, packet, MAXPACKET, 0, fromsockaddr, &fromsockaddrsize);
  LOGMSG_("got %zd bytes", sz);
  int minfailsz, minsz =
#ifdef ENABLE_IPV6
    (af == AF_INET6) ? sizeof(struct ip6_hdr) :
#endif
    sizeof(struct _iphdr);

  uint8_t *data;
  struct _icmphdr *icmp;
  minsz = offsets(packet, minsz, (uint8_t**)&icmp, &data, &minfailsz);
  if (sz < minsz)
    LOGRET_("incorrect packet size %zd [af=%d proto=%d minsz=%d]", sz, af, mtrtype, minsz);

#ifdef WITH_MPLS
  bool mplson = false;
#endif
  int seq = -1, reason = -1;
  switch (mtrtype) {
    case IPPROTO_ICMP: {
      if (icmp->type == echoreplytype) {
        reason = RE_PONG;
        ICMPSEQID;
      } else if ((icmp->type == timeexceededtype) || (icmp->type == unreachabletype)) {
        if (sz < minfailsz)
          LOGRET_("incorrect packet size %zd [af=%d proto=%d expect>=%d]", sz, af, mtrtype, minfailsz);
        reason = (icmp->type == timeexceededtype) ? RE_EXCEED : RE_UNREACH;
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
      /*summ*/ net_replies[QR_SUM]++; net_replies[QR_ICMP]++;
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
      /*summ*/ net_replies[QR_SUM]++; net_replies[QR_UDP]++;
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
      /*summ*/ net_replies[QR_SUM]++; net_replies[QR_TCP]++;
    } break;
  } /*end of switch*/

  if (seq >= 0)
    net_stat(seq, fromaddress, now, reason MPLSFNTAIL(mplson ? decodempls(data, sz - (data - packet)) : NULL));
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
    if (addr_equal(&CURRENT_IP(at), remoteaddress)) {
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
    // [every cycle] Randomize bit-pattern and packet-size if they are less than 0
    bitpattern = (cbitpattern < 0) ? RANDUNIFORM(256) : cbitpattern;
    if (cpacketsize < 0) {
      int base = -cpacketsize - MINPACKET;
      packetsize = base ? (MINPACKET + RANDUNIFORM(base)) : MINPACKET;
    } else
      packetsize = cpacketsize;
  }

  bool ping = true;
  if (cache_mode)
    if (host[batch_at].up && (host[batch_at].seen > 0))
      if ((time(NULL) - host[batch_at].seen) <= cache_timeout)
        ping = false;
  if (ping && !net_send(batch_at))
    LOG_RE(-1, "failed");

  int n_unknown = 0;
  for (int at = fstTTL - 1; at < batch_at; at++) {
    if (!addr_exist(&CURRENT_IP(at)))
      n_unknown++;
    if (addr_equal(&CURRENT_IP(at), remoteaddress))
      n_unknown = MAXHOST; // Make sure we drop into "we should restart"
  }

  if (addr_equal(&CURRENT_IP(batch_at), remoteaddress) // success in reaching target
     || (n_unknown > MAX_UNKNOWN_HOSTS) // fail in consecuitive MAX_UNKNOWN_HOSTS (firewall?)
     || (batch_at >= (maxTTL - 1))      // or reach limit
     || (batch_at >= stopper)) {        // or learnt unreachable
    numhosts = batch_at + 1;
    batch_at = fstTTL - 1;
    LOGMSG_("stop at hop #%d", numhosts);
    return 1;
  }

  batch_at++;
  return 0;
}

static void net_sock_close(void) {
  CLOSE(sendsock4);
  CLOSE(recvsock4);
#ifdef ENABLE_IPV6
  CLOSE(sendsock6_icmp);
  CLOSE(sendsock6_udp);
  CLOSE(recvsock6);
#endif
}

#define WARNCLRE(sock, msg) { if ((sock) < 0) { WARN(msg); net_sock_close(); return false; }; /*summ*/ sum_sock[0]++; }

bool net_open(void) { // optional IPv6: no error
  net_init(0);  // no IPv6 by default
  sendsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sendsock4 < 0) sendsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // backup
  WARNCLRE(sendsock4, "send socket");
  recvsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  WARNCLRE(recvsock4, "recv socket");
#ifdef ENABLE_IPV6
  sendsock6_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  WARNCLRE(sendsock6_icmp, "send ICMP socket6");
  sendsock6_udp = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
  WARNCLRE(sendsock6_udp, "send UDP socket6");
  recvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  WARNCLRE(recvsock6, "recv socket6");
#endif
#ifdef IP_HDRINCL
  // FreeBSD wants this to avoid sending out packets with protocol type RAW to the network
  int trueopt = 1;
  if (setsockopt(sendsock4, 0, IP_HDRINCL, &trueopt, sizeof(trueopt))) {
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
  else if (mtrtype == IPPROTO_UDP) sendsock6 = sendsock6_udp;
}
#endif

bool net_set_host(struct hostent *h) {
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr *name = (struct sockaddr *) &name_struct;
  remotesockaddr->sa_family = h->h_addrtype;

  switch (h->h_addrtype) {
  case AF_INET:
    sendsock = sendsock4;
    recvsock = recvsock4;
    addr_copy(&(rsa4->sin_addr), h->h_addr);
    sourceaddress = (ip_t*) &(ssa4->sin_addr);
    remoteaddress = (ip_t*) &(rsa4->sin_addr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if ((sendsock6 < 0) || (recvsock6 < 0)) {
      WARNX("Unable to open IPv6 socket");
      return false;
    }
    sendsock = sendsock6;
    recvsock = recvsock6;
    addr_copy(&(rsa6->sin6_addr), h->h_addr);
    sourceaddress = (ip_t*) &(ssa6->sin6_addr);
    remoteaddress = (ip_t*) &(rsa6->sin6_addr);
    break;
#endif
  default:
    WARNX_("Unknown address type %d", h->h_addrtype);
    return false;
  }

  if (!addr_exist(remoteaddress)) {
    WARNX("Unspecified destination");
    return false;
  }

  net_reset();
  socklen_t len = sizeof(name_struct);
  getsockname(recvsock, name, &len);
  sockaddrtop(name, localaddr, sizeof(localaddr));
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
  clock_gettime(CLOCK_MONOTONIC, &reset);
  batch_at = fstTTL - 1;
  stopper = MAXHOST;
  numhosts = 10;
}


bool net_set_ifaddr(char *ifaddr) {
  int len = 0;
  sourcesockaddr->sa_family = af;
  switch (af) {
    case AF_INET:
      ssa4->sin_port = 0;
      if (!inet_aton(ifaddr, &(ssa4->sin_addr))) {
        WARNX_("bad address %s", ifaddr);
        return false;
      }
      len = sizeof(struct sockaddr);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      ssa6->sin6_port = 0;
      if (inet_pton(af, ifaddr, &(ssa6->sin6_addr)) < 1) {
        WARNX_("bad IPv6 address %s", ifaddr);
        return false;
      }
      len = sizeof(struct sockaddr_in6);
      break;
#endif
  }
  if (bind(sendsock, sourcesockaddr, len) < 0) {
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

/* Similar to inet_ntop but uses a sockaddr as it's argument. */
void sockaddrtop(struct sockaddr *saddr, char *strptr, size_t len) {
  struct sockaddr_in *sa4;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *sa6;
#endif
  switch (saddr->sa_family) {
  case AF_INET:
    sa4 = (struct sockaddr_in *) saddr;
    strncpy(strptr, inet_ntoa(sa4->sin_addr), len - 1);
    strptr[len - 1] = '\0';
    return;
#ifdef ENABLE_IPV6
  case AF_INET6:
    sa6 = (struct sockaddr_in6 *) saddr;
    inet_ntop(sa6->sin6_family, &(sa6->sin6_addr), strptr, len);
    return;
#endif
  default:
    WARNX_("Unknown address type %d", saddr->sa_family);
    strptr[0] = '\0';
    return;
  }
}

static int err_slippage(int sock) {
  struct sockaddr *addr = NULL;
  socklen_t namelen;
  switch (af) {
    case AF_INET:
      addr = (struct sockaddr *)rsa4;
      namelen = sizeof(*rsa4);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      addr = (struct sockaddr *)rsa6;
      namelen = sizeof(*rsa6);
      break;
#endif
  }

  int r = getpeername(sock, addr, &namelen);
  if ((r < 0) && (errno == ENOTCONN)) {
    r = read(sock, &namelen, 1);
    if (r >= 0) // sanity lost
      return -1;
    r = errno;
  } else
    r = 0;
  return r;
}

// Check connection state with error-slippage
void net_tcp_parse(int sock, int seq, int noerr) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  int reason = -1, e = err_slippage(sock);
  LOGMSG_("recv <e=%d> sock=%d ts=%lld.%09ld", e, sock, (long long)now.tv_sec, now.tv_nsec);
  // if no errors, or connection refused, or host down, the target is probably reached
  switch (e) {
    case EHOSTUNREACH:
    case ENETUNREACH:
      reason = RE_UNREACH;
    case EHOSTDOWN:
    case ECONNREFUSED:
    case 0: // no error
      net_stat(seq, remoteaddress, now, reason MPLSFNTAIL(NULL)); /*no MPLS decoding?*/
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
  clock_gettime(CLOCK_MONOTONIC, &now);
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
  assert(sizeof(struct _iphdr) == 20);
  assert(sizeof(struct _icmphdr) == 8);
  assert(sizeof(struct udp_ph) == 12);
#ifdef WITH_MPLS
  assert(ies_sz == 4);
  assert(ieo_sz == 4);
  assert(lab_sz == 4);
#endif
}

void net_init(int ipv6) {
#ifdef ENABLE_DNS
  dns_ptr_handler = save_ptr_answer; // no checks, handler for net-module only
#endif
#ifdef ENABLE_IPV6
  if (ipv6) {
    af = AF_INET6;
    addr_exist = addr6exist;
    addr_equal = addr6equal;
    addr_copy  = addr6copy;
  } else
#endif
  { // IPv4 by default
    af = AF_INET;
    addr_exist = addr4exist;
    addr_equal = addr4equal;
    addr_copy  = addr4copy;
  }
}

const char *strlongip(ip_t *ip) {
  static char addrstr[INET6_ADDRSTRLEN];
  return inet_ntop(af, ip, addrstr, sizeof(addrstr));
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

