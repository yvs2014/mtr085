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

#include <stdlib.h>
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

#ifdef LOG_NET
#include <syslog.h>
#define NETLOG_MSG(format, ...) { syslog(LOG_PRIORITY, format, __VA_ARGS__); }
#define NETLOG_RET(format, ...) { syslog(LOG_PRIORITY, format, __VA_ARGS__); return; }
#else
#define NETLOG_MSG(format, ...)  {}
#define NETLOG_RET(format, ...)  { return; }
#endif

#ifdef __OpenBSD__
#define ABS llabs
#define LLD "%lld"
#else
#define ABS labs
#define LLD "%ld"
#endif

/*  We can't rely on header files to provide this information, because
    the fields have different names between, for instance, Linux and
    Solaris  */
struct ICMPHeader {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t sequence;
};

/* Structure of an IPv4 UDP pseudoheader.  */
struct UDPv4PHeader {
  uint32_t saddr;
  uint32_t daddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t len;
};

/*  Structure of an IP header.  */
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

struct sequence {
  int index;
  int transit;
  int saved_seq;
  struct timeval time;
};

// global vars
ip_t unspec_addr;	// zero by definition
bool (*addr_spec)(const void *); // true if address is specified
bool (*addr_equal)(const void *, const void *); // true if it's the same address
int (*unaddrcmp)(const void *);
int (*addrcmp)(const void *, const void *);
void* (*addrcpy)(void *, const void *);
int af;	// address family
int packetsize;	// packet size used by ping
struct nethost host[MAXHOST];
char localaddr[INET6_ADDRSTRLEN];
//

static unsigned *tcp_sockets;


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

#ifdef ENABLE_IPV6
static struct sockaddr_storage sourcesockaddr_struct;
static struct sockaddr_storage remotesockaddr_struct;
static struct sockaddr_in6 * ssa6 = (struct sockaddr_in6 *) &sourcesockaddr_struct;
static struct sockaddr_in6 * rsa6 = (struct sockaddr_in6 *) &remotesockaddr_struct;
#else
static struct sockaddr_in sourcesockaddr_struct;
static struct sockaddr_in remotesockaddr_struct;
#endif

static struct sockaddr * sourcesockaddr = (struct sockaddr *) &sourcesockaddr_struct;
static struct sockaddr * remotesockaddr = (struct sockaddr *) &remotesockaddr_struct;
static struct sockaddr_in * ssa4 = (struct sockaddr_in *) &sourcesockaddr_struct;
static struct sockaddr_in * rsa4 = (struct sockaddr_in *) &remotesockaddr_struct;

static ip_t * sourceaddress;
static ip_t * remoteaddress;

static int batch_at;
static int numhosts = 10;
static int portpid;
static int stopper = MAXHOST;
enum RE_REASONS { RE_PONG, RE_EXCEED, RE_UNREACH };

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

int net_tcp_init(void) {
  if (!tcp_sockets)
    if (!(tcp_sockets = calloc(SEQ_MAX, sizeof(int)))) {
      perror("net_tcp_init()");
      return 0;
    }
  return 1;
}
 
#define ERR_N_EXIT(s) { \
  int e = errno; \
  display_clear(); \
  fprintf(stderr, "%s: %s\n", s, strerror(e)); \
  exit(e); \
}

#define NST_ADRR_FILL(lo_addr, ssa_addr, re_addr, re_port, loc) { \
  addrcpy(&lo_addr, &ssa_addr); \
  addrcpy(&re_addr, remoteaddress); \
  re_port = htons((remoteport > 0) ? remoteport : TCP_DEFAULT_PORT); \
  namelen = sizeof(*loc); \
}

// Attempt to connect to a TCP port with a TTL
static void net_send_tcp(int index) {
  struct sockaddr_storage local;
  struct sockaddr_storage remote;
  struct sockaddr_in *local4 = (struct sockaddr_in *) &local;
  struct sockaddr_in *remote4 = (struct sockaddr_in *) &remote;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 *local6 = (struct sockaddr_in6 *) &local;
  struct sockaddr_in6 *remote6 = (struct sockaddr_in6 *) &remote;
#endif
  socklen_t len;

  int ttl = index + 1;

  int s = socket(af, SOCK_STREAM, 0);
  if (s < 0)
    ERR_N_EXIT("socket()");

  memset(&local, 0, sizeof (local));
  memset(&remote, 0, sizeof (remote));
  local.ss_family = af;
  remote.ss_family = af;

  socklen_t namelen = sizeof(local);
  switch (af) {
  case AF_INET:
    NST_ADRR_FILL(local4->sin_addr, ssa4->sin_addr, remote4->sin_addr, remote4->sin_port, local4);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    NST_ADRR_FILL(local6->sin6_addr, ssa6->sin6_addr, remote6->sin6_addr, remote6->sin6_port, local6);
    break;
#endif
  }

  if (bind(s, (struct sockaddr *) &local, namelen))
    ERR_N_EXIT("bind()");

  len = sizeof (local);
  if (getsockname(s, (struct sockaddr *) &local, &len))
    ERR_N_EXIT("getsockname()");

  int opt = 1;
  if (ioctl(s, FIONBIO, &opt))
    ERR_N_EXIT("ioctl FIONBIO");

  switch (af) {
  case AF_INET:
    if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl)))
      ERR_N_EXIT("setsockopt IP_TTL");
    if (setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof (tos)))
      ERR_N_EXIT("setsockopt IP_TOS");
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof (ttl)))
      ERR_N_EXIT("setsockopt IP_TTL");
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
    ERR_N_EXIT("unknown AF?");
  }

  int pseq = port % SEQ_MAX;
  save_sequence(index, pseq);
  gettimeofday(&sequence[pseq].time, NULL);

  if (tcp_sockets)
    tcp_sockets[pseq] = s;

  connect(s, (struct sockaddr *) &remote, namelen);
  FD_SET(s, &wset);
  if (s >= maxfd)
    maxfd = s + 1;
  NETLOG_MSG("net_send_tcp(index=%d): sequence=%d, socket=%d", index, pseq, s);
}

#define SET_UDP_UH_PORTS(sport, dport) { \
  udp->uh_sport = htons(sport); \
  udp->uh_dport = htons(dport); \
}

#ifdef __FreeBSD_version
#if __FreeBSD_version >= 1100000
#define IPLEN_RAW(sz) htons(sz)
#endif
#elif __OpenBSD__
#define IPLEN_RAW(sz) htons(sz)
#else
#define IPLEN_RAW(sz) sz
#endif

// Attempt to find the host at a particular number of hops away
static void net_send_query(int index) {
  char packet[MAXPACKET];
  struct IPHeader *ip = (struct IPHeader *)packet;
  struct ICMPHeader*icmp = NULL;
  struct udphdr *udp = NULL;
  struct UDPv4PHeader *udpp = NULL;
  int iphsize = 0, echotype = 0, salen = 0;
  int ttl = index + 1;

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
      ERR_N_EXIT("setsockopt IP_TOS");
    if (setsockopt(sendsock, IPPROTO_IP, IP_TTL, &ttl, sizeof ttl))
      ERR_N_EXIT("setsockopt IP_TTL");
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
    addrcpy(&(ip->saddr), &(ssa4->sin_addr));
    addrcpy(&(ip->daddr), remoteaddress);
#endif
    echotype = ICMP_ECHO;
    salen = sizeof (struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    iphsize = 0;
    if (setsockopt(sendsock, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof ttl))
      ERR_N_EXIT("setsockopt IPV6_UNICAST_HOPS");
    echotype = ICMP6_ECHO_REQUEST;
    salen = sizeof (struct sockaddr_in6);
    break;
#endif
  }

  if (mtrtype == IPPROTO_ICMP) {
    icmp = (struct ICMPHeader *)(packet + iphsize);
    icmp->type     = echotype;
    icmp->code     = 0;
    icmp->checksum = 0;
    icmp->id       = mypid;
    icmp->sequence = new_sequence(index);
    icmp->checksum = checksum(icmp, packetsize - iphsize);
    gettimeofday(&sequence[icmp->sequence].time, NULL);
    NETLOG_MSG("net_send_icmp(index=%d): sequence=%d", index, icmp->sequence);
  } else if (mtrtype == IPPROTO_UDP) {
    udp = (struct udphdr *)(packet + iphsize);
    udp->uh_sum  = 0;
    udp->uh_ulen = htons(packetsize - iphsize);
    int useq = new_sequence(index);
    if (remoteport < 0) {
      SET_UDP_UH_PORTS(portpid, (LO_UDPPORT + useq));
	} else {
      SET_UDP_UH_PORTS((LO_UDPPORT + useq), remoteport);
    };

    gettimeofday(&sequence[useq].time, NULL);
    NETLOG_MSG("net_send_udp(index=%d): sequence=%d, port=%d", index, useq, ntohs(udp->uh_dport));
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
        ERR_N_EXIT("setsockopt IPV6_CHECKSUM");
    }
#endif
  }

  if (sendto(sendsock, packet, packetsize, 0, remotesockaddr, salen) < 0)
    ERR_N_EXIT("sendto()");
}

static void tcp_seq_close(unsigned at) {
  if (!tcp_sockets)
    return;
  unsigned fd = tcp_sockets[at];
  if (fd) {
    tcp_sockets[at] = 0;
    close(fd);
    FD_CLR(fd, &wset);
    if ((fd + 1) == maxfd)
      maxfd--;
  }
}


static void fill_host_stat(int at, time_t curr, int saved_seq) {
  host[at].jitter = ABS(curr - host[at].last);
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
    if (!addrcmp(&IP_AT_NDX(hop, i), addr))
      return i;
  return -1;
}

int at2next(int hop) { // return first free slot at 'hop', otherwise -1
  for (int i = 0; i < MAXPATH; i++)
    if (!unaddrcmp(&IP_AT_NDX(hop, i)))
      return i;
  return -1;
}

// set new ip-addr and clear associated data
void set_new_addr(int at, int ndx, const ip_t *ip, const mpls_data_t *mpls) {
  addrcpy(&IP_AT_NDX(at, ndx), ip);
  mpls ? memcpy(&MPLS_AT_NDX(at, ndx), mpls, sizeof(mpls_data_t))
    : memset(&MPLS_AT_NDX(at, ndx), 0, sizeof(mpls_data_t));
  if (Q_AT_NDX(at, ndx)) {
    free(Q_AT_NDX(at, ndx));
    Q_AT_NDX(at, ndx) = NULL;
  }
  if (R_AT_NDX(at, ndx)) {
    free(R_AT_NDX(at, ndx));
    R_AT_NDX(at, ndx) = NULL;
  }
}

// We got a return on something
static void net_process_ping(unsigned port, const mpls_data_t *mpls, const void *addr, struct timeval now, int reason) {
  unsigned seq = port % SEQ_MAX;
  if (!sequence[seq].transit)
    return;

  NETLOG_MSG("net_process_ping(port=%d, seq=%d)", port, seq);
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
  addrcpy(&copy, addr); // can it be overwritten?
  int ndx = addr2ndx(at, &copy);
  if (ndx < 0) {        // new one
    ndx = at2next(at);
    if (ndx < 0) {      // no free slots? warn about it, and change the last one
      fprintf(stderr, "MAXPATH=%d is exceeded at hop=%d\n", MAXPATH, at);
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
  if (enable_raw) {
    NETLOG_MSG("raw_rawping(at=%d, curr[usec]=" LLD ")", at, curr);
    raw_rawping(at, curr);
  }
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
    to something we sent, then call net_process_ping()  */
void net_process_return(void) {
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
  NETLOG_MSG("net_process_return(): got %d bytes", num);
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
      NETLOG_MSG("ICMP: net_process_return(): id=%u, seq=%d, type=%d, code=%d",
        header->id, sequence, header->type, header->code);
    }
    break;

  case IPPROTO_UDP: {
      struct udphdr *uh = NULL;
      switch ( af ) {
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
      NETLOG_MSG("UDP: net_process_return: portpid=%d, seq=%d", portpid, sequence);
    }
    break;

  case IPPROTO_TCP: {
      struct tcphdr *th = NULL;
      switch ( af ) {
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
      NETLOG_MSG("TCP: net_process_return(): sequence=%d", sequence);
    }
    break;
  }

  if (sequence >= 0)
    net_process_ping(sequence, &mpls, fromaddress, now, reason);
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
    if (!addrcmp(&CURRENT_IP(at), remoteaddress)) {
      max = at + 1;
      if (endpoint_mode)
        fstTTL = max;
      break;
    } else if (unaddrcmp(&CURRENT_IP(at))) {
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
    if (!unaddrcmp(&CURRENT_IP(at)))
      n_unknown++;
    if (!addrcmp(&CURRENT_IP(at), remoteaddress))
      n_unknown = MAXHOST; // Make sure we drop into "we should restart"
  }

  if (!addrcmp(&CURRENT_IP(batch_at), remoteaddress) // success in reaching target
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


static void set_fd_flags(int fd) {
  int oldflags;
  if (fd < 0)
    return;
  oldflags = fcntl(fd, F_GETFD);
  if (oldflags == -1) {
    perror("Couldn't get fd's flags");
    return;
  }
#ifdef FD_CLOEXEC
  if (fcntl(fd, F_SETFD, oldflags | FD_CLOEXEC))
    perror("Couldn't set fd's flags");
#endif
}

int net_preopen(void) {
  int trueopt = 1;

#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
  sendsock4_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  sendsock4_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
#else
  sendsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
#endif
  if (sendsock4 < 0)
    return -1;
#ifdef ENABLE_IPV6
  sendsock6_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  sendsock6_udp = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
#endif

#ifdef IP_HDRINCL
  /*  FreeBSD wants this to avoid sending out packets with protocol type RAW
      to the network.  */
  if (setsockopt(sendsock4, SOL_IP, IP_HDRINCL, &trueopt, sizeof(trueopt))) {
    perror("setsockopt(IP_HDRINCL,1)");
    return -1;
  }
#endif /* IP_HDRINCL */

  recvsock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (recvsock4 < 0)
    return -1;
  set_fd_flags(recvsock4);
#ifdef ENABLE_IPV6
  recvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (recvsock6 >= 0)
     set_fd_flags(recvsock6);
#endif

  return 0;
}


int net_selectsocket(void) {
#if !defined(IP_HDRINCL) && defined(IP_TOS) && defined(IP_TTL)
  switch ( mtrtype ) {
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
  switch ( mtrtype ) {
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

int net_open(struct hostent *entry) {
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr * name = (struct sockaddr *) &name_struct;

  net_reset();
  remotesockaddr->sa_family = entry->h_addrtype;

  switch (entry->h_addrtype) {
  case AF_INET:
    sendsock = sendsock4;
    recvsock = recvsock4;
    addr4cpy(&(rsa4->sin_addr), entry->h_addr);
    sourceaddress = (ip_t *) &(ssa4->sin_addr);
    remoteaddress = (ip_t *) &(rsa4->sin_addr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (sendsock6 < 0 || recvsock6 < 0) {
      fprintf(stderr, "Could not open IPv6 socket\n");
      exit(EXIT_FAILURE);
    }
    sendsock = sendsock6;
    recvsock = recvsock6;
    addr6cpy(&(rsa6->sin6_addr), entry->h_addr);
    sourceaddress = (ip_t *) &(ssa6->sin6_addr);
    remoteaddress = (ip_t *) &(rsa6->sin6_addr);
    break;
#endif
  default:
    fprintf(stderr, "net_open bad address type\n");
    exit(EXIT_FAILURE);
  }

  socklen_t len = sizeof(name_struct);
  getsockname(recvsock, name, &len);
  sockaddrtop(name, localaddr, sizeof(localaddr));
  portpid = IPPORT_RESERVED + mypid % (65535 - IPPORT_RESERVED);
  return 0;
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
  for (int at = 0; at < SEQ_MAX; at++) {
    sequence[at].transit = 0;
    if (mtrtype == IPPROTO_TCP)
      tcp_seq_close(at);
  }
  gettimeofday(&reset, NULL);
  batch_at = fstTTL - 1;
  stopper = MAXHOST;
  numhosts = 10;
}


int net_set_interfaceaddress(char *InterfaceAddress) {
  int len = 0;
  if (!InterfaceAddress)
    return 0;

  sourcesockaddr->sa_family = af;
  switch (af) {
    case AF_INET:
      ssa4->sin_port = 0;
      if (inet_aton(InterfaceAddress, &(ssa4->sin_addr)) < 1) {
        fprintf(stderr, "bad interface address: %s\n", InterfaceAddress);
        return 1;
      }
      len = sizeof(struct sockaddr);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      ssa6->sin6_port = 0;
      if (inet_pton(af, InterfaceAddress, &(ssa6->sin6_addr)) < 1) {
        fprintf(stderr, "bad interface address: %s\n", InterfaceAddress);
        return 1;
      }
      len = sizeof(struct sockaddr_in6);
      break;
#endif
  }

  if (bind(sendsock, sourcesockaddr, len) < 0) {
    perror("failed to bind to interface");
    return 1;
  }
  return 0;
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
}

int net_waitfd(void) {
  return recvsock;
}

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
    fprintf(stderr, "sockaddrtop unknown address type\n");
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

// check if we got connection or error on any fds
bool net_process_tcp_fds(void) {
  if (!tcp_sockets)
    return false;

  struct timeval now;
  time_t unow, utime;

  /* ??? can't do MPLS decoding */
  mpls_data_t mpls;
  mpls.n = 0;

  gettimeofday(&now, NULL);
  unow = timer2usec(&now);

  bool ret = false;
  for (int at = 0; at < SEQ_MAX; at++) {
    unsigned fd = tcp_sockets[at];
    if (fd) {
      if (FD_ISSET(fd, &wset)) {
//        r = write(fd, "G", 1);
        errno = err_slippage(fd);
        bool r = errno ? false : true; // like write()
        /* if write was successful, or connection refused we have
         * (probably) reached the remote address. Anything else happens to the
         * connection, we write it off to avoid leaking sockets */
        if (r || (errno == ECONNREFUSED)) {
          net_process_ping(at, &mpls, remoteaddress, now, -1);
          ret = true;
//        } else if ((errno != EAGAIN) && (errno != EHOSTUNREACH)) {
//          sequence[at].transit = 0;
//          tcp_seq_close(at);
        }
      }
      utime = timer2usec(&(sequence[at].time));
      if (unow - utime > tcp_timeout) {
        NETLOG_MSG("close sequence[%d] after %d sec", at, tcp_timeout / 1000000);
        sequence[at].transit = 0;
        tcp_seq_close(at);
      }
    }
  }
  return ret;
}

bool addr4spec(const void *a) { // comparison to unspecified IPv4 address
  return memcmp(a, &unspec_addr, sizeof(struct in_addr)) ? true : false;
}
bool addr4equal(const void *a, const void *b) { // IPv4 address comparison
  return memcmp(a, b, sizeof(struct in_addr)) ? false : true;
}
int unaddr4cmp(const void *a) { // comparison to unspecified IPv4 address
  return memcmp(a, &unspec_addr, sizeof(struct in_addr));
}
int addr4cmp(const void *a, const void *b) { // IPv4 address comparison
  return memcmp(a, b, sizeof(struct in_addr));
}
void* addr4cpy(void *a, const void *b) { // IPv4 address copy
  return memcpy(a, b, sizeof(struct in_addr));
}

#ifdef ENABLE_IPV6
bool addr6spec(const void *a) { // comparison to unspecified IPv6 address
  return memcmp(a, &unspec_addr, sizeof(struct in6_addr)) ? true : false;
}
bool addr6equal(const void *a, const void *b) { // IPv6 address comparison
  return memcmp(a, b, sizeof(struct in6_addr)) ? false : true;
}
int unaddr6cmp(const void *a) { // comparison to unspecified IPv6 address
  return memcmp(a, &unspec_addr, sizeof(struct in6_addr));
}
int addr6cmp(const void *a, const void *b) { // IPv6 address comparison
  return memcmp(a, b, sizeof(struct in6_addr));
}
void* addr6cpy(void *a, const void *b) { // IPv6 address copy
  return memcpy(a, b, sizeof(struct in6_addr));
}
#endif

void net_init(int ipv6_mode) {
#ifdef ENABLE_IPV6
  if (ipv6_mode) {
    af = AF_INET6;
    addr_spec = addr6spec;
    addr_equal = addr6equal;
    unaddrcmp = unaddr6cmp;
    addrcmp = addr6cmp;
    addrcpy = addr6cpy;
  } else
#endif
  { // IPv4 by default
    af = AF_INET;
    addr_spec = addr4spec;
    addr_equal = addr4equal;
    unaddrcmp = unaddr4cmp;
    addrcmp = addr4cmp;
    addrcpy = addr4cpy;
  }
}

const char *strlongip(ip_t *ip) {
  static char addrstr[INET6_ADDRSTRLEN];
  return inet_ntop(af, ip, addrstr, sizeof(addrstr));
}

static const char mpls_fmt[] = "%*s[Lbl:%u Exp:%u S:%u TTL:%u]";

const char *mpls2str(const mpls_label_t *label, int indent) {
  static char m2s_buf[64];
  snprintf(m2s_buf, sizeof(m2s_buf), mpls_fmt, indent, "", label->lab, label->exp, label->s, label->ttl);
  return m2s_buf;
}

