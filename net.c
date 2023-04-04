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
#include <errno.h>
#include <limits.h>
#include <math.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "config.h"
#include "mtr.h"
#include "net.h"
#include "select.h"
#include "display.h"
#include "dns.h"
#include "report.h"

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "macros.h"

/*  We can't rely on header files to provide this information, because
    the fields have different names between, for instance, Linux and Solaris  */
struct ICMPHeader {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t sequence;
};

// Structure of an IPv4 UDP pseudoheader
struct UDPv4PHeader {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
};

// Structure of an IP header
struct IPHeader {
  uint8_t version;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t frag;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
};

#ifndef SOL_IP
#define SOL_IP 0
#endif

#define SEQ_MAX 16384

#define LO_UDPPORT 33433	// start from LO_UDPPORT+1
#define UDPPORTS 90		// go thru udp:33434-33523 acl
#define TCP_DEFAULT_PORT 80

#define SET_UDP_UH_PORTS(uh, s, d) { (uh)->uh_sport = htons(s); (uh)->uh_dport = htons(d); }

// and not forget to include sys/param.h
#ifdef __FreeBSD_version
#if __FreeBSD_version >= 1100000
#define IPLEN_RAW(sz) htons(sz)
#endif
#elif __OpenBSD__
#define IPLEN_RAW(sz) htons(sz)
#else
#define IPLEN_RAW(sz) sz
#endif

struct sequence {
  int index;
  int transit;
  int saved_seq;
  struct timeval time;
};

// global vars
ip_t unspec_addr;	// zero by definition
bool (*addr_exist)(const void *); // true if address is specified
bool (*addr_equal)(const void *, const void *); // equal
void* (*addr_copy)(void *, const void *);
int af;	// address family
int packetsize;	// packet size used by ping
struct nethost host[MAXHOST];
char localaddr[INET6_ADDRSTRLEN];
unsigned long net_queries[4]; // number of queries (sum, icmp, udp, tcp)
unsigned long net_replies[4]; // number of replies (sum, icmp, udp, tcp)
//


/* How many queries to unknown hosts do we send?
 * It limits the amount of traffic generated if a host is not reachable
 */
#define MAX_UNKNOWN_HOSTS 10

static struct sequence sequence[SEQ_MAX];
static struct timeval reset;

static int sendsock4 = -1;
static int sendsock4_icmp = -1;
static int sendsock4_udp = -1;
static int recvsock4 = -1;
static int sendsock6 = -1;
static int sendsock6_icmp = -1;
static int sendsock6_udp = -1;
static int recvsock6 = -1;
static int sendsock = -1;
static int recvsock = -1;
static int *tsockets;

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
enum RE_REASONS { RE_PONG, RE_EXCEED, RE_UNREACH };


bool addr4exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in_addr)) ? true : false; }
bool addr4equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in_addr)) ? false : true; }
void* addr4copy(void *a, const void *b) { return memcpy(a, b, sizeof(struct in_addr)); }
#ifdef ENABLE_IPV6
bool addr6exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in6_addr)) ? true : false; }
bool addr6equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in6_addr)) ? false : true; }
void* addr6copy(void *a, const void *b) { return memcpy(a, b, sizeof(struct in6_addr)); }
#endif

// return the number of microseconds to wait before sending the next ping
time_t wait_usec(float t) {
  int n = numhosts;
  int f = fstTTL - 1;
  if ((f > 0) && (n > f))
    n -= f;
  t /= n;
  return 1000000 * t;
}

static unsigned short checksum(const void *data, int sz) {
  const unsigned short *ch = data;
  unsigned sum = 0;
  for (; sz > 1; sz -= 2)
    sum += *ch++;
  if (sz)
    sum += *(unsigned char *)ch;
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return ~sum;
}

// Prepend pseudoheader to the udp datagram and calculate checksum
static int udp_checksum(void *pheader, void *udata, int psize, int dsize) {
  unsigned tsize = psize + dsize;
  char csumpacket[tsize];
  memset(csumpacket, (unsigned char) abs(bitpattern), tsize);

  struct UDPv4PHeader *prepend = (struct UDPv4PHeader *) csumpacket;
  struct UDPv4PHeader *udppheader = (struct UDPv4PHeader *) pheader;
  prepend->saddr = udppheader->saddr;
  prepend->daddr = udppheader->daddr;
  prepend->zero = 0;
  prepend->protocol = udppheader->protocol;
  prepend->len = udppheader->len;

  struct udphdr *content = (struct udphdr *)(csumpacket + psize);
  struct udphdr *udpdata = (struct udphdr *)udata;
  content->uh_sport = udpdata->uh_sport;
  content->uh_dport = udpdata->uh_dport;
  content->uh_ulen = udpdata->uh_ulen;
  content->uh_sum = udpdata->uh_sum;

  return checksum(csumpacket,tsize);
}

static void save_sequence(int index, int seq) {
  sequence[seq].index = index;
  sequence[seq].transit = 1;
  sequence[seq].saved_seq = ++host[index].xmit;
  memset(&sequence[seq].time, 0, sizeof(sequence[seq].time));

  host[index].transit = 1;
  if (host[index].sent)
    host[index].up = 0;
  host[index].sent = 1;

  if (host[index].saved[SAVED_PINGS - 1] != -2) {
    for (int at = 0; at < MAXHOST; at++) {
      memmove(host[at].saved, host[at].saved + 1, (SAVED_PINGS - 1) * sizeof(int));
      host[at].saved[SAVED_PINGS - 1] = -2;
      host[at].saved_seq_offset += 1;
    }
  }
  host[index].saved[SAVED_PINGS - 1] = -1;
}

static int new_sequence(int index) {
  static int max_seqs[] = { [IPPROTO_ICMP] = SEQ_MAX, [IPPROTO_UDP] = UDPPORTS };
  static int next_sequence;
  int seq = next_sequence++;
  if (next_sequence >= max_seqs[mtrtype])
    next_sequence = 0;
  save_sequence(index, seq);
  return seq;
}

bool net_tcp_init(void) {
  if (!tsockets) {
    size_t sz = SEQ_MAX * sizeof(int);
    tsockets = malloc(sz);
    (tsockets) ? memset(tsockets, -1, sz) : WARN_("malloc(%zd)", sz);
  }
  return tsockets ? true : false;
}
 
#define EXIT(s) { int e = errno; display_clear(); ERRX_(e, "%s: %s", s, strerror(e)); }

#define SET_TCP_ATTR(lo_addr, ssa_addr, re_addr, re_port, paddr) { \
  addr_copy(&lo_addr, &ssa_addr); \
  addr_copy(&re_addr, remoteaddress); \
  re_port = htons((remoteport > 0) ? remoteport : TCP_DEFAULT_PORT); \
  addrlen = sizeof(*paddr); \
}

// Attempt to connect to a TCP port with a TTL
static void net_send_tcp(int index) {
  if (!tsockets)
    EXIT("No tcp sockets available");

  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
#endif

  int ttl = index + 1;
  int s = socket(af, SOCK_STREAM, 0);
  if (s < 0)
    EXIT("socket");

  memset(&local, 0, sizeof (local));
  memset(&remote, 0, sizeof (remote));
  local.ss_family = af;
  remote.ss_family = af;

  socklen_t addrlen;
#ifdef ENABLE_IPV6
  if (af == AF_INET6) SET_TCP_ATTR(local6->sin6_addr, ssa6->sin6_addr, remote6->sin6_addr, remote6->sin6_port, local6) else
#endif
  SET_TCP_ATTR(local4->sin_addr, ssa4->sin_addr, remote4->sin_addr, remote4->sin_port, local4);
  if (bind(s, (struct sockaddr *) &local, addrlen))
    EXIT("bind");

  if (getsockname(s, (struct sockaddr *) &local, &addrlen))
    EXIT("getsockname");

  int opt = 1;
  if (ioctl(s, FIONBIO, &opt))
    EXIT("ioctl");

  switch (af) {
  case AF_INET:
    if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)))
      EXIT("setsockopt IP_TTL");
    if (setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)))
      EXIT("setsockopt IP_TOS");
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)))
      EXIT("setsockopt IP_TTL");
    break;
#endif
  }

  int port;
  switch (local.ss_family) {
  case AF_INET:
    port = ntohs(local4->sin_port);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    port = ntohs(local6->sin6_port);
    break;
#endif
  default:
    EXIT("unknown AF?");
  }

  int pseq = port % SEQ_MAX;
  save_sequence(index, pseq);
  gettimeofday(&sequence[pseq].time, NULL);
  tsockets[pseq] = s;
  connect(s, (struct sockaddr *) &remote, addrlen);
  /*stat*/ net_queries[0]++; net_queries[2]++;
  FD_SET(s, &wset);
  if (s >= maxfd)
    maxfd = s + 1;
  LOGMSG_("ndx=%d seq=%d sock=%d", index, pseq, s);
}

// Attempt to find the host at a particular number of hops away
static void net_send_query(int at) {
  char packet[MAXPACKET];
  struct IPHeader *ip = (struct IPHeader *)packet;
  struct ICMPHeader*icmp = NULL;
  struct udphdr *udp = NULL;
  struct UDPv4PHeader *udpp = NULL;
  int iphsize = 0, echotype = 0, salen = 0;
  int ttl = at + 1;

#ifdef ENABLE_IPV6
  /* offset for ipv6 checksum calculation */
  int offset = 6;
#endif

  if (packetsize < MINPACKET) packetsize = MINPACKET;
  else if (packetsize > MAXPACKET) packetsize = MAXPACKET;
  memset(packet, (unsigned char) abs(bitpattern), packetsize);

  switch (af) {
  case AF_INET:
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
    iphsize = 0;
    if (setsockopt(sendsock, IPPROTO_IP, IP_TOS, &tos, sizeof tos))
      EXIT("setsockopt IP_TOS");
    if (setsockopt(sendsock, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl))
      EXIT("setsockopt IP_TTL");
#else
    iphsize = sizeof(struct IPHeader);
    ip->version = 0x45;
    ip->tos = tos;
    ip->len = IPLEN_RAW(packetsize);
    ip->id = 0;
    ip->frag = 0;
    ip->ttl = ttl;
    ip->protocol = mtrtype;
    ip->check = 0;

  /* BSD needs the source address here, Linux & others do not... */
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
      EXIT("setsockopt IPV6_UNICAST_HOPS");
    echotype = ICMP6_ECHO_REQUEST;
    salen = sizeof(struct sockaddr_in6);
    break;
#endif
  }

  if (mtrtype == IPPROTO_ICMP) {
    icmp = (struct ICMPHeader *)(packet + iphsize);
    icmp->type     = echotype;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = mypid;
    icmp->sequence = new_sequence(at);
    icmp->checksum = checksum(icmp, packetsize - iphsize);
    gettimeofday(&sequence[icmp->sequence].time, NULL);
    LOGMSG_("icmp: ndx=%d seq=%d id=%u", at, icmp->sequence, icmp->id);
  } else if (mtrtype == IPPROTO_UDP) {
    udp = (struct udphdr *)(packet + iphsize);
    udp->uh_sum  = 0;
    udp->uh_ulen = htons(packetsize - iphsize);
    int useq = new_sequence(at);
    if (remoteport < 0)
      SET_UDP_UH_PORTS(udp, portpid, LO_UDPPORT + useq)
    else
      SET_UDP_UH_PORTS(udp, LO_UDPPORT + useq, remoteport);

    gettimeofday(&sequence[useq].time, NULL);
    LOGMSG_("udp: ndx=%d seq=%d port=%u", at, useq, ntohs(udp->uh_dport));
    if (af == AF_INET) {
      /* checksum is not mandatory. only calculate if we know ip->saddr */
      if (ip->saddr) {
        udpp = (struct UDPv4PHeader *)(malloc(sizeof(struct UDPv4PHeader)));
        udpp->saddr = ip->saddr;
        udpp->daddr = ip->daddr;
        udpp->protocol = ip->protocol;
        udpp->len = udp->uh_ulen;
        udp->uh_sum = udp_checksum(udpp, udp, sizeof(struct UDPv4PHeader), packetsize - iphsize);
        if (!udp->uh_sum)
          udp->uh_sum = 0xffff;
      }
    }
#ifdef ENABLE_IPV6
    else if (af == AF_INET6) {
      /* kernel checksum calculation */
      if (setsockopt(sendsock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)))
        EXIT("setsockopt IPV6_CHECKSUM");
    }
#endif
  }

  if (sendto(sendsock, packet, packetsize, 0, remotesockaddr, salen) < 0)
    EXIT("sendto");
  /*stat*/ net_queries[0]++; (mtrtype == IPPROTO_ICMP) ? net_queries[1]++ : net_queries[2];
}

static void tcp_seq_close(int at) {
  sequence[at].transit = 0;
  int fd;
  if (!tsockets || ((fd = tsockets[at]) < 0))
    return;
  close(fd);
  FD_CLR(fd, &wset);
  if ((fd + 1) == maxfd)
    maxfd--;
  tsockets[at] = -1;
}


static void fill_host_stat(int at, time_t curr, int saved_seq) {
  int dj = curr - host[at].last;
  host[at].jitter = (dj < 0) ? -dj : dj;
  host[at].last = curr;

  if (host[at].returned < 1) {
    host[at].best = host[at].worst = host[at].gmean = curr;
    host[at].avg = host[at].var = host[at].jitter = host[at].jworst = host[at].jinta = 0;
  }

  if (curr < host[at].best)
     host[at].best = curr;
  if (curr > host[at].worst)
     host[at].worst = curr;
  if (host[at].jitter > host[at].jworst)
     host[at].jworst = host[at].jitter;

  host[at].returned++;
  int oldavg = host[at].avg;
  host[at].avg += ((double)(curr - oldavg)) / host[at].returned;
  host[at].var += ((double)(curr - oldavg)) * (curr - host[at].avg) / 1000000;

  int oldjavg = host[at].javg;
  host[at].javg += (host[at].jitter - oldjavg) / host[at].returned;
  /* below algorithm is from rfc1889, A.8 */
  host[at].jinta += host[at].jitter - ((host[at].jinta + 8) >> 4);

  if (host[at].returned > 1)
    host[at].gmean =
      pow((double)host[at].gmean, (host[at].returned - 1.0) / host[at].returned)
      * pow((double)curr, 1.0 / host[at].returned);
  host[at].sent = 0;
  host[at].up = 1;
  host[at].transit = 0;
  if (cache_mode)
    host[at].seen = time(NULL);

  int ndx = saved_seq - host[at].saved_seq_offset;
  if ((ndx >= 0) && (ndx <= SAVED_PINGS))
    host[at].saved[ndx] = curr;
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

// set new ip-addr and clear associated data
void set_new_addr(int at, int ndx, const ip_t *ip, const mpls_data_t *mpls) {
  addr_copy(&IP_AT_NDX(at, ndx), ip);
  mpls ? memcpy(&MPLS_AT_NDX(at, ndx), mpls, sizeof(mpls_data_t))
    : memset(&MPLS_AT_NDX(at, ndx), 0, sizeof(mpls_data_t));
  if (QPTR_AT_NDX(at, ndx)) {
    free(QPTR_AT_NDX(at, ndx));
    QPTR_AT_NDX(at, ndx) = NULL;
  }
  if (RPTR_AT_NDX(at, ndx)) {
    free(RPTR_AT_NDX(at, ndx));
    RPTR_AT_NDX(at, ndx) = NULL;
  }
#ifdef IPINFO
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

// We got a return on something
static void net_stat(unsigned port, const mpls_data_t *mpls, const void *addr, struct timeval now, int reason) {
  unsigned seq = port % SEQ_MAX;
  if (!sequence[seq].transit)
    return;

  LOGMSG_("seq=%d", seq);
  sequence[seq].transit = 0;
  if (mtrtype == IPPROTO_TCP)
    tcp_seq_close(seq);

  int at = sequence[seq].index;
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
    set_new_addr(at, ndx, &copy, mpls);
#ifdef OUTPUT_FORMAT_RAW
    if (enable_raw)
      raw_rawhost(at, &IP_AT_NDX(at, ndx));
#endif
  }

  struct timeval _tv;
  timersub(&now, &(sequence[seq].time), &_tv);
  time_t curr = timer2usec(&_tv); // is negative possible? [if (curr < 0) curr = 0;]
  fill_host_stat(at, curr, sequence[seq].saved_seq);
#ifdef OUTPUT_FORMAT_RAW
  if (enable_raw)
    raw_rawping(at, curr);
#endif
}

#define FDATA_OFF	(sizeof(struct IPHeader) + sizeof(struct ICMPHeader) + sizeof(struct IPHeader))
#define FDATA6_OFF	(sizeof(struct ICMPHeader) + sizeof(struct ip6_hdr))

#define USER_DATA(header, data_off, head_struct, lim) { \
  if (num < (data_off + 8)) \
    return; \
  if (num > lim) \
    decodempls(num, packet, &mpls, lim - 4); \
  header = (head_struct *)(packet + data_off); \
}

#define NPR_FILL_SADDR(sa_in, sa_addr, icmp_er, icmp_te, icmp_un) { \
    fromsockaddrsize = sizeof(struct sa_in); \
    fromaddress = (ip_t *) &(sa_addr); \
    echoreplytype = icmp_er; \
    timeexceededtype = icmp_te; \
    unreachabletype = icmp_un; \
}

/*  We know a packet has come in, because the main select loop has called us,
    now we just need to read it, see if it is for us, and if it is a reply
    to something we sent, then call net_stat()  */
void net_parse(void) {
  unsigned char packet[MAXPACKET];
#ifdef ENABLE_IPV6
  struct sockaddr_storage fromsockaddr_struct;
  struct sockaddr_in6 * fsa6 = (struct sockaddr_in6 *) &fromsockaddr_struct;
#else
  struct sockaddr_in fromsockaddr_struct;
#endif
  struct sockaddr * fromsockaddr = (struct sockaddr *) &fromsockaddr_struct;
  struct sockaddr_in * fsa4 = (struct sockaddr_in *) &fromsockaddr_struct;
  socklen_t fromsockaddrsize;
  int num;
  struct ICMPHeader *header = NULL;
  struct timeval now;
  ip_t * fromaddress = NULL;
  int echoreplytype = 0, timeexceededtype = 0, unreachabletype = 0;

  /* MPLS decoding */
  mpls_data_t mpls;
  mpls.n = 0;

  gettimeofday(&now, NULL);
  switch (af) {
  case AF_INET:
#ifndef ICMP_TIME_EXCEEDED  // old systems' compatibility
#define ICMP_TIME_EXCEEDED  11
#endif
    NPR_FILL_SADDR(sockaddr_in, fsa4->sin_addr, ICMP_ECHOREPLY, ICMP_TIME_EXCEEDED, ICMP_UNREACH);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    NPR_FILL_SADDR(sockaddr_in6, fsa6->sin6_addr, ICMP6_ECHO_REPLY, ICMP6_TIME_EXCEEDED, ICMP6_DST_UNREACH);
    break;
#endif
  }

  num = recvfrom(recvsock, packet, MAXPACKET, 0, fromsockaddr, &fromsockaddrsize);
  LOGMSG_("got %d bytes", num);
  switch (af) {
  case AF_INET:
    if (num < (sizeof(struct IPHeader) + sizeof(struct ICMPHeader)))
      return;
    header = (struct ICMPHeader *)(packet + sizeof(struct IPHeader));
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (num < sizeof(struct ICMPHeader))
      return;
    header = (struct ICMPHeader *)packet;
    break;
#endif
  }

  int sequence = -1, reason = -1;

  switch (mtrtype) {
  case IPPROTO_ICMP:
    if (header->type == echoreplytype) {
      if (header->id != (uint16_t)mypid)
        return;
      sequence = header->sequence;
      reason = RE_PONG;
    } else if ((header->type == timeexceededtype) || (header->type == unreachabletype)) {
      reason = (header->type == timeexceededtype) ? RE_EXCEED : RE_UNREACH;
      switch (af) {
      case AF_INET:
        USER_DATA(header, FDATA_OFF, struct ICMPHeader, 160);
      break;
#ifdef ENABLE_IPV6
      case AF_INET6:
        USER_DATA(header, FDATA6_OFF, struct ICMPHeader, 140);
      break;
#endif
      }
      if (header->id != (uint16_t)mypid)
        return;
      sequence = header->sequence;
      LOGMSG_("icmp: id=%u seq=%d type=%d code=%d", header->id, sequence, header->type, header->code);
    }
    /*stat*/ net_replies[0]++; net_replies[1]++;
    break;

  case IPPROTO_UDP: {
      struct udphdr *uh = NULL;
      switch (af) {
      case AF_INET:
        USER_DATA(uh, FDATA_OFF, struct udphdr, 160);
      break;
#ifdef ENABLE_IPV6
      case AF_INET6:
        USER_DATA(uh, FDATA6_OFF, struct udphdr, 140);
      break;
#endif
      }
      if (remoteport < 0) {
        if (ntohs(uh->uh_sport) != portpid)
          return;
        sequence = ntohs(uh->uh_dport);
      } else {
        if (ntohs(uh->uh_dport) != remoteport)
          return;
        sequence = ntohs(uh->uh_sport);
      }
      sequence -= LO_UDPPORT;
      LOGMSG_("udp: id=%d seq=%d", portpid, sequence);
    }
    /*stat*/ net_replies[0]++; net_replies[2]++;
    break;

  case IPPROTO_TCP: {
      struct tcphdr *th = NULL;
      switch (af) {
      case AF_INET:
        USER_DATA(th, FDATA_OFF, struct tcphdr, 160);
      break;
#ifdef ENABLE_IPV6
      case AF_INET6:
        USER_DATA(th, FDATA6_OFF, struct tcphdr, 140);
      break;
#endif
      }
      sequence = ntohs(th->th_sport);
      LOGMSG_("tcp: seq=%d", sequence);
    }
    /*stat*/ net_replies[0]++; net_replies[3]++;
    break;
  }

  if (sequence >= 0)
    net_stat(sequence, &mpls, fromaddress, now, reason);
}

int net_elem(int at, char c) {
  switch (c) {	// mtr.c:data_fields[]
    case 'D':	// Dropped Packets
      return (host[at].xmit - host[at].transit) - host[at].returned;
    case 'L':	// Loss Ratio (times extra 1000)
      return (host[at].xmit - host[at].transit) ? (1000 * (100 - (100.0 * host[at].returned / (host[at].xmit - host[at].transit)))) : 0;
    case 'R':	// Received Packets
      return host[at].returned;
    case 'S':	// Sent Packets
      return host[at].xmit;
    case 'N':	// Newest RTT(ms)
      return host[at].last;
    case 'B':	// Min/Best RTT(ms)
      return host[at].best;
    case 'A':	// Average RTT(ms)
      return host[at].avg;
    case 'W':	// Max/Worst RTT(ms)
      return host[at].worst;
    case 'V':	// Standard Deviation
      return (host[at].returned > 1) ? (1000.0 * sqrt(host[at].var / (host[at].returned - 1.0))) : 0;
    case 'G':	// Geometric Mean
      return host[at].gmean;
    case 'J':	// Current Jitter
      return host[at].jitter;
    case 'M':	// Jitter Mean/Avg
      return host[at].javg;
    case 'X':	// Worst Jitter
      return host[at].jworst;
    case 'I':	// Interarrival Jitter
      return host[at].jinta;
  }
  return 0;
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

int net_min (void) {
  return (fstTTL - 1);
}

void net_end_transit(void) {
  for (int at = 0; at < MAXHOST; at++)
    host[at].transit = 0;
}

int net_send_batch(void) {
  /* randomized packet size and/or bit pattern if packetsize<0 and/or
     bitpattern<0.  abs(packetsize) and/or abs(bitpattern) will be used
  */
  if (batch_at < fstTTL) {
    /* Someone used a formula here that tried to correct for the
       "end-error" in "rand()". By "end-error" I mean that if you
       have a range for "rand()" that runs to 32768, and the
       destination range is 10000, you end up with 4 out of 32768
       0-2768's and only 3 out of 32768 for results 2769 .. 9999.
       As our destination range (in the example 10000) is much
       smaller (reasonable packet sizes), and our rand() range much
       larger, this effect is insignificant. Oh! That other formula
       didn't work. */
    packetsize = (cpacketsize >= 0) ? cpacketsize : (MINPACKET + rand() % (-cpacketsize - MINPACKET));
    if (bitpattern < 0)
      bitpattern = - (int)(256 + 255 * (rand() / (RAND_MAX + 0.1)));
  }

  bool ping = true;
  if (cache_mode)
    if (host[batch_at].up && (host[batch_at].seen > 0))
      if ((time(NULL) - host[batch_at].seen) <= cache_timeout)
        ping = false;
  if (ping)
    (mtrtype == IPPROTO_TCP) ? net_send_tcp(batch_at) : net_send_query(batch_at);

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
    return 1;
  }

  batch_at++;
  return 0;
}

bool net_open(void) { // optional IPv6: no error
  net_init(0);  // no IPv6 by default

#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
  sendsock4_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sendsock4_icmp < 0) {
    WARN("ICMP raw socket");
    return false;
  }
  sendsock4_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sendsock4_udp < 0) {
    WARN("UDP raw socket");
    return false;
  }
#else
  sendsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sendsock4 < 0) {
    WARN("raw socket");
    return false;
  }
#endif
#ifdef IP_HDRINCL
  /*  FreeBSD wants this to avoid sending out packets with protocol type RAW to the network */
  int trueopt = 1;
  if (setsockopt(sendsock4, SOL_IP, IP_HDRINCL, &trueopt, sizeof(trueopt))) {
    WARN("setsockopt(IP_HDRINCL,1)");
    return false;
  }
#endif
#ifdef ENABLE_IPV6
  sendsock6_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (sendsock6_icmp < 0)
    WARN("ICMP raw socket6");
  sendsock6_udp = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
  if (sendsock6_udp < 0)
    WARN("UDP raw socket6");
#endif

  recvsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (recvsock4 < 0) {
    WARN("raw socket");
    return false;
  }
#ifdef ENABLE_IPV6
  recvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (recvsock6 < 0)
    WARN("raw socket6");
#endif

  return true;
}


int net_selectsocket(void) {
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
  switch (mtrtype) {
  case IPPROTO_ICMP:
    sendsock4 = sendsock4_icmp;
    break;
  case IPPROTO_UDP:
    sendsock4 = sendsock4_udp;
    break;
  }
#endif
  if (sendsock4 < 0)
    return -1;
#ifdef ENABLE_IPV6
  switch (mtrtype) {
  case IPPROTO_ICMP:
    sendsock6 = sendsock6_icmp;
    break;
  case IPPROTO_UDP:
    sendsock6 = sendsock6_udp;
    break;
  }
  if ((sendsock6 < 0) && (sendsock4 < 0))
    return -1;
#endif

 return 0;
}


bool net_set_host(struct hostent *h) {
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr *name = (struct sockaddr *) &name_struct;

  net_reset();
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
    if ((sendsock6 < 0) || (recvsock6 < 0))
      FAIL("Unable to open IPv6 socket");
    sendsock = sendsock6;
    recvsock = recvsock6;
    addr_copy(&(rsa6->sin6_addr), h->h_addr);
    sourceaddress = (ip_t*) &(ssa6->sin6_addr);
    remoteaddress = (ip_t*) &(rsa6->sin6_addr);
    break;
#endif
  default:
    FAIL_("Unknown address type %d", h->h_addrtype);
  }

  socklen_t len = sizeof(name_struct);
  getsockname(recvsock, name, &len);
  sockaddrtop(name, localaddr, sizeof(localaddr));
  portpid = IPPORT_RESERVED + mypid % (65535 - IPPORT_RESERVED);
  return true;
}

void net_reset(void) {
  for (int at = 0; at < MAXHOST; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      set_new_addr(at, ndx, &unspec_addr, NULL); // clear all query/response cache
  memset(host, 0, sizeof(host));
  for (int at = 0; at < MAXHOST; at++) {
    for (int i = 0; i < SAVED_PINGS; i++)
      host[at].saved[i] = -2;	// unsent
    host[at].saved_seq_offset = -SAVED_PINGS + 2;
  }
  for (int at = 0; at < SEQ_MAX; at++)
    if (mtrtype == IPPROTO_TCP)
      tcp_seq_close(at);
  gettimeofday(&reset, NULL);
  batch_at = fstTTL - 1;
  stopper = MAXHOST;
  numhosts = 10;
}


bool net_set_ifaddr(char *ifaddr) {
  if (!ifaddr)
    return true;

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
  if (sendsock4 >= 0) {
    close(sendsock4_icmp);
    close(sendsock4_udp);
  }
  if (recvsock4 >= 0) close(recvsock4);
  if (sendsock6 >= 0) {
    close(sendsock6_icmp);
    close(sendsock6_udp);
  }
  if (recvsock6 >= 0) close(recvsock6);
  // clear memory allocated for query/response cache
  for (int at = 0; at < MAXHOST; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      set_new_addr(at, ndx, &unspec_addr, NULL);
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

// Decode MPLS
void decodempls(int num, const uint8_t *packet, mpls_data_t *mpls, int off) {
  /* loosely derived from the traceroute-nanog.c decoding by Jorge Boncompte */
  uint32_t ver = packet[off] >> 4;
  uint32_t res = packet[off++] & 15;   // +1
  res += packet[off++];                // +2
  uint32_t chk = packet[off++] << 8;   // +3
  chk += packet[off++];                // +4
  // Check for ICMP extension header
  if ((ver == 2) && (res == 0) && chk && (num >= (off + 2))) {
    uint32_t len = packet[off++] << 8; // +5
    len += packet[off++];              // +6
    uint8_t class = packet[off++];     // +7
    uint8_t type  = packet[off++];     // +8
    // make sure we have an MPLS extension
    if ((len >= 8) && (class == 1) && (type == 1)) {
      uint8_t n = (len - 4) / 4;
      mpls->n = (n > MAXLABELS) ? MAXLABELS : n;
      for (int i = 0; (i < mpls->n) && (num >= off); i++) {
        // piece together the 20 byte label value
        uint32_t l = packet[off++] << 12;       // +1
        l |= packet[off++] << 4;                // +2
        l |= packet[off] >> 4;
        mpls->label[i].lab = l;
        mpls->label[i].exp = (packet[off] >> 1) & 0x7;
        mpls->label[i].s = packet[off++] & 0x1; // +3
        mpls->label[i].ttl = packet[off++];     // +4
      }
    }
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

// check if we got connection or not
bool net_tcp_parse(void) {
  static const mpls_data_t mpls; // empty (can't do MPLS decoding?)
  if (!tsockets)
    return false;

  struct timeval now;
  gettimeofday(&now, NULL);
  time_t unow = timer2usec(&now);

  bool re = false;
  for (int at = 0, fd; at < SEQ_MAX; at++) {
    if ((fd = tsockets[at]) < 0)
      continue;
    if (FD_ISSET(fd, &wset)) {
//    r = write(fd, "G", 1);
      errno = err_slippage(fd);
      bool r = errno ? false : true; // like write()
      /* if write was successful, or connection refused we have
       * (probably) reached the remote address. Anything else happens to the
       * connection, we write it off to avoid leaking sockets */
      if (r || (errno == ECONNREFUSED)) {
        net_stat(at, &mpls, remoteaddress, now, -1);
        re = true;
      } // else if ((errno != EAGAIN) && (errno != EHOSTUNREACH)) tcp_seq_close(at);
    }
    if ((unow - timer2usec(&sequence[at].time)) > tcp_timeout) {
      LOGMSG_("close seq=%d after %d sec", at, tcp_timeout / 1000000);
      tcp_seq_close(at);
    }
  }
  return re;
}

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

void net_init(int ipv6) {
  dns_ptr_handler = save_ptr_answer; // no checks, handler for net-module only
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

const char *mpls2str(const mpls_label_t *label, int indent) {
  static const char mpls_fmt[] = "%*s[Lbl:%u Exp:%u S:%u TTL:%u]";
  static char m2s_buf[64];
  snprintf(m2s_buf, sizeof(m2s_buf), mpls_fmt, indent, "", label->lab, label->exp, label->s, label->ttl);
  return m2s_buf;
}

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

