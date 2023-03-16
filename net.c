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

#include "config.h"

#ifndef _BSD_SOURCE
#define _BSD_SOURCE 1
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <memory.h>
#include <unistd.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "mtr.h"
#include "net.h"
#include "select.h"
#include "display.h"
#include "dns.h"
#include "report.h"

#ifdef LOG_NET
#include <syslog.h>
#define NETLOG_MSG(x)   { syslog x ; }
#define NETLOG_ERR(x)   { syslog x ; return; }
#else
#define NETLOG_MSG(x)   {}
#define NETLOG_ERR(x)   { return; }
#endif

/*  We can't rely on header files to provide this information, because
    the fields have different names between, for instance, Linux and
    Solaris  */
struct ICMPHeader {
  uint8 type;
  uint8 code;
  uint16 checksum;
  uint16 id;
  uint16 sequence;
};

/* Structure of an IPv4 UDP pseudoheader.  */
struct UDPv4PHeader {
  uint32 saddr;
  uint32 daddr;
  uint8 zero;
  uint8 protocol;
  uint16 len;
};

/*  Structure of an IP header.  */
struct IPHeader {
  uint8 version;
  uint8 tos;
  uint16 len;
  uint16 id;
  uint16 frag;
  uint8 ttl;
  uint8 protocol;
  uint16 check;
  uint32 saddr;
  uint32 daddr;
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
int (*unaddrcmp)(const void *);
int (*addrcmp)(const void *a, const void *b);
void* (*addrcpy)(void *a, const void *b);
int af;	// address family
int packetsize;	// packet size used by ping
struct nethost host[MAXHOST];
char localaddr[INET6_ADDRSTRLEN];
int cycles;
//

static unsigned *tcp_sockets;


/* How many queries to unknown hosts do we send?
 * It limits the amount of traffic generated if a host is not reachable
 */
#define MAX_UNKNOWN_HOSTS 10

static struct sequence sequence[SEQ_MAX];
static struct timeval reset;

static int sendsock4;
static int sendsock4_icmp;
static int sendsock4_udp;
static int recvsock4;
static int sendsock6;
static int sendsock6_icmp;
static int sendsock6_udp;
static int recvsock6;
static int sendsock;
static int recvsock;

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
 
#define ERR_N_EXIT(s) { display_clear(); perror(s); exit(EXIT_FAILURE);}

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
  NETLOG_MSG((LOG_INFO, "net_send_tcp(index=%d): sequence=%d, socket=%d", index, pseq, s));
}

#define SET_UDP_UH_PORTS(sport, dport) { \
  udp->uh_sport = htons(sport); \
  udp->uh_dport = htons(dport); \
}

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
    ip->len = packetsize;
    ip->id = 0;
    ip->frag = 0;    /* 1, if want to find mtu size? Min */
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
    NETLOG_MSG((LOG_INFO, "net_send_icmp(index=%d): sequence=%d", index, icmp->sequence));
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
    NETLOG_MSG((LOG_INFO, "net_send_udp(index=%d): sequence=%d, port=%d", index, useq, ntohs(udp->uh_dport)));
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

  sendto(sendsock, packet, packetsize, 0, remotesockaddr, salen);
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

// We got a return on something we sent out. Record the address and time.
static void net_process_ping(unsigned port, struct mplslen mpls, void *addr, struct timeval now) {
  ip_t addrcopy;

  /* Copy the from address ASAP because it can be overwritten */
  addrcpy(&addrcopy, addr);

  unsigned seq = port % SEQ_MAX;
  if (!sequence[seq].transit)
    return;

  NETLOG_MSG((LOG_INFO, "net_process_ping(port=%d, seq=%d)", port, seq));
  sequence[seq].transit = 0;
  if (mtrtype == IPPROTO_TCP)
    tcp_seq_close(seq);

  int index = sequence[seq].index;
  struct timeval _tv;
  timersub(&now, &(sequence[seq].time), &_tv);
  time_t totusec = timer2usec(&_tv); // impossible? [if (totusec < 0) totusec = 0;]

  if (!unaddrcmp(&(host[index].addr))) {
    /* should be out of if as addr can change */
    addrcpy(&(host[index].addr), &addrcopy);
    host[index].mpls = mpls;
#ifdef OUTPUT_FORMAT_RAW
    if (enable_raw)
      raw_rawhost(index, &(host[index].addr));
#endif
    /* multi paths */
    addrcpy(&(host[index].addrs[0]), &addrcopy);
    host[index].mplss[0] = mpls;
  } else {
    int i = 0;
    for (; i < MAXPATH; i++)
      if (!addrcmp(&(host[index].addrs[i]), &addrcopy) || !unaddrcmp(&(host[index].addrs[i])))
        break;
    if (addrcmp(&(host[index].addrs[i]), &addrcopy) && (i < MAXPATH)) {
      addrcpy(&(host[index].addrs[i]), &addrcopy);
      host[index].mplss[i] = mpls;
#ifdef OUTPUT_FORMAT_RAW
      if (enable_raw)
        raw_rawhost(index, &(host[index].addrs[i]));
#endif
    }
  }

  host[index].jitter = abs(totusec - host[index].last);
  host[index].last = totusec;

  if (host[index].returned < 1) {
    host[index].best = host[index].worst = host[index].gmean = totusec;
    host[index].avg = host[index].var = host[index].jitter = host[index].jworst = host[index].jinta = 0;
  }

  if (totusec < host[index].best)
     host[index].best = totusec;
  if (totusec > host[index].worst)
     host[index].worst = totusec;
  if (host[index].jitter > host[index].jworst)
     host[index].jworst = host[index].jitter;

  host[index].returned++;
  int oldavg = host[index].avg;
  host[index].avg += ((double)(totusec - oldavg)) / host[index].returned;
  host[index].var += ((double)(totusec - oldavg)) * (totusec - host[index].avg) / 1000000;

  int oldjavg = host[index].javg;
  host[index].javg += (host[index].jitter - oldjavg) / host[index].returned;
  /* below algorithm is from rfc1889, A.8 */
  host[index].jinta += host[index].jitter - ((host[index].jinta + 8) >> 4);

  if (host[index].returned > 1)
    host[index].gmean =
      pow((double)host[index].gmean, (host[index].returned - 1.0) / host[index].returned)
      * pow((double)totusec, 1.0 / host[index].returned);
  host[index].sent = 0;
  host[index].up = 1;
  host[index].transit = 0;
  if (cache_mode)
    host[index].seen = time(NULL);

  int ndx = sequence[seq].saved_seq - host[index].saved_seq_offset;
  if ((ndx >= 0) && (ndx <= SAVED_PINGS))
    host[index].saved[ndx] = totusec;

#ifdef OUTPUT_FORMAT_RAW
  if (enable_raw) {
    NETLOG_MSG((LOG_INFO, "raw_rawping(index=%d, totusec=%d)", index, totusec));
    raw_rawping(index, totusec);
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
  char packet[MAXPACKET];
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
  struct mplslen mpls;
  mpls.labels = 0;

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
  NETLOG_MSG((LOG_INFO, "net_process_return(): got %d bytes", num));
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

  int sequence = -1;

  switch (mtrtype) {
  case IPPROTO_ICMP:
    if (header->type == echoreplytype) {
      if (header->id != (uint16)mypid)
        return;
      sequence = header->sequence;
    } else if ((header->type == timeexceededtype) || (header->type == unreachabletype)) {
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

      if (header->id != (uint16)mypid)
        return;
      sequence = header->sequence;
      NETLOG_MSG((LOG_INFO, "ICMP: net_process_return(): id=%d, seq=%d", header->id, sequence));
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
      NETLOG_MSG((LOG_INFO, "UDP: net_process_return: portpid=%d, seq=%d", portpid, sequence));
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
      NETLOG_MSG((LOG_INFO, "TCP: net_process_return(): sequence=%d", sequence));
    }
    break;
  }

  if (sequence >= 0)
    net_process_ping(sequence, mpls, fromaddress, now);
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
    if (!addrcmp(&(host[at].addr), remoteaddress)) {
      max = at + 1;
      if (endpoint_mode)
        fstTTL = max;
      break;
    } else if (unaddrcmp(&(host[at].addr))) {
      if (endpoint_mode)
        fstTTL = at + 1;
      max = at + 2;
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
  for (int i = fstTTL - 1; i < batch_at; i++) {
    if (!unaddrcmp(&(host[i].addr)))
      n_unknown++;

    /* The second condition in the next "if" statement was added in mtr-0.56,
	but I don't remember why. It makes mtr stop skipping sections of unknown
	hosts. Removed in 0.65.
	If the line proves neccesary, it should at least NOT trigger that line
	when host[i].addr == 0 */
    if (!addrcmp(&(host[i].addr), remoteaddress)
	/* || (host[i].addr == host[batch_at].addr)  */)
      n_unknown = MAXHOST; // Make sure we drop into "we should restart"
  }

  if (!addrcmp(&(host[batch_at].addr), remoteaddress)	// success in reaching target
     || (n_unknown > MAX_UNKNOWN_HOSTS)	// fail in consecuitive MAX_UNKNOWN_HOSTS (firewall?)
     || (batch_at >= (maxTTL - 1))) {	// or reach limit
    numhosts = batch_at + 1;
    batch_at = fstTTL - 1;
    if (cache_mode)
      cycles++; // to see progress on curses screen
    return 1;
  }

  batch_at++;
  return 0;
}


static void set_fd_flags(int fd) {
#if defined(HAVE_FCNTL) && defined(FD_CLOEXEC)
  int oldflags;

  if (fd < 0) return;

  oldflags = fcntl(fd, F_GETFD);
  if (oldflags == -1) {
    perror("Couldn't get fd's flags");
    return;
  }
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

int net_open(struct hostent * host) {
#ifdef ENABLE_IPV6
  struct sockaddr_storage name_struct;
#else
  struct sockaddr_in name_struct;
#endif
  struct sockaddr * name = (struct sockaddr *) &name_struct;
  socklen_t len;

  net_reset();

  remotesockaddr->sa_family = host->h_addrtype;

  switch ( host->h_addrtype ) {
  case AF_INET:
    sendsock = sendsock4;
    recvsock = recvsock4;
    addr4cpy(&(rsa4->sin_addr), host->h_addr);
    sourceaddress = (ip_t *) &(ssa4->sin_addr);
    remoteaddress = (ip_t *) &(rsa4->sin_addr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    if (sendsock6 < 0 || recvsock6 < 0) {
      fprintf( stderr, "Could not open IPv6 socket\n" );
      exit( EXIT_FAILURE );
    }
    sendsock = sendsock6;
    recvsock = recvsock6;
    addr6cpy(&(rsa6->sin6_addr), host->h_addr);
    sourceaddress = (ip_t *) &(ssa6->sin6_addr);
    remoteaddress = (ip_t *) &(rsa6->sin6_addr);
    break;
#endif
  default:
    fprintf( stderr, "net_open bad address type\n" );
    exit( EXIT_FAILURE );
  }

  len = sizeof name_struct;
  getsockname(recvsock, name, &len);
  sockaddrtop(name, localaddr, sizeof(localaddr));

  portpid = IPPORT_RESERVED + mypid % (65535 - IPPORT_RESERVED);
  return 0;
}

void net_reopen(struct hostent * addr) {
  memset(host, 0, sizeof(host));
  remotesockaddr->sa_family = addr->h_addrtype;

  switch (addr->h_addrtype) {
  case AF_INET:
    addr4cpy(remoteaddress, addr->h_addr);
    addr4cpy(&(rsa4->sin_addr), addr->h_addr);
    break;
#ifdef ENABLE_IPV6
  case AF_INET6:
    addr6cpy(remoteaddress, addr->h_addr);
    addr6cpy(&(rsa6->sin6_addr), addr->h_addr);
    break;
#endif
  default:
    fprintf( stderr, "net_reopen bad address type\n" );
    exit( EXIT_FAILURE );
  }

  net_reset ();
  net_send_batch();
}


void net_reset(void) {
  batch_at = fstTTL - 1;	/* above replacedByMin */
  numhosts = 10;

  for (int at = 0; at < MAXHOST; at++) {
    host[at].xmit = 0;
    host[at].transit = 0;
    host[at].returned = 0;
    host[at].sent = 0;
    host[at].up = 0;
    host[at].last = 0;
    host[at].avg  = 0;
    host[at].best = 0;
    host[at].worst = 0;
    host[at].gmean = 0;
    host[at].var = 0;
    host[at].jitter = 0;
    host[at].javg = 0;
    host[at].jworst = 0;
    host[at].jinta = 0;
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

  if (bind(sendsock, sourcesockaddr, len) == -1) {
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
void sockaddrtop( struct sockaddr * saddr, char * strptr, size_t len ) {
  struct sockaddr_in *  sa4;
#ifdef ENABLE_IPV6
  struct sockaddr_in6 * sa6;
#endif

  switch ( saddr->sa_family ) {
  case AF_INET:
    sa4 = (struct sockaddr_in *) saddr;
    strncpy( strptr, inet_ntoa( sa4->sin_addr ), len - 1 );
    strptr[ len - 1 ] = '\0';
    return;
#ifdef ENABLE_IPV6
  case AF_INET6:
    sa6 = (struct sockaddr_in6 *) saddr;
    inet_ntop( sa6->sin6_family, &(sa6->sin6_addr), strptr, len );
    return;
#endif
  default:
    fprintf( stderr, "sockaddrtop unknown address type\n" );
    strptr[0] = '\0';
    return;
  }
}

// Decode MPLS
void decodempls(int num, char *packet, struct mplslen *mpls, int offset) {
  unsigned ext_ver, ext_res, ext_chk, obj_hdr_len;
  u_char obj_hdr_class, obj_hdr_type;

  /* loosely derived from the traceroute-nanog.c
   * decoding by Jorge Boncompte */
  ext_ver = packet[offset]>>4;
  ext_res = (packet[offset]&15)+ packet[offset+1];
  ext_chk = ((unsigned)packet[offset+2]<<8)+packet[offset+3];

  /* Check for ICMP extension header */
  if (ext_ver == 2 && ext_res == 0 && ext_chk != 0 && num >= (offset+6)) {
    obj_hdr_len = ((int)packet[offset+4]<<8)+packet[offset+5];
    obj_hdr_class = packet[offset+6];
    obj_hdr_type = packet[offset+7];

    /* make sure we have an MPLS extension */
    if ((obj_hdr_len >= 8) && (obj_hdr_class == 1) && (obj_hdr_type == 1)) {
      /* how many labels do we have?  will be at least 1 */
      mpls->labels = (obj_hdr_len-4)/4;

      // save all label objects
      for (int i = 0, j = offset + 8; (i < mpls->labels) && (i < MAXLABELS) && (num >= j); i++, j += i * 4) {
        // piece together the 20 byte label value
        unsigned long lab = (packet[j] << 12) & 0xff000;
        lab += (packet[j + 1] << 4) & 0xff0;
        lab += (packet[j + 2] >> 4) & 0xf;
        mpls->label[i] = lab;
        mpls->exp[i] = (packet[j + 2] >> 1) & 0x7;
        mpls->s[i]   = packet[j + 2] & 0x1; // should be 1 if only one label
        mpls->ttl[i] = packet[j + 3];
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

  /* Can't do MPLS decoding */
  struct mplslen mpls;
  mpls.labels = 0;

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
          net_process_ping(at, mpls, remoteaddress, now);
          ret = true;
//        } else if ((errno != EAGAIN) && (errno != EHOSTUNREACH)) {
//          sequence[at].transit = 0;
//          tcp_seq_close(at);
        }
      }
      utime = timer2usec(&(sequence[at].time));
      if (unow - utime > tcp_timeout) {
        NETLOG_MSG((LOG_INFO, "close sequence[%d] after %d sec", at, tcp_timeout / 1000000));
        sequence[at].transit = 0;
        tcp_seq_close(at);
      }
    }
  }
  return ret;
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
    unaddrcmp = unaddr6cmp;
    addrcmp = addr6cmp;
    addrcpy = addr6cpy;
  } else
#endif
  { // IPv4 by default
    af = AF_INET;
    unaddrcmp = unaddr4cmp;
    addrcmp = addr4cmp;
    addrcpy = addr4cpy;
  }
}

const char *strlongip(ip_t *ip) {
  static char addrstr[INET6_ADDRSTRLEN];
  return inet_ntop(af, ip, addrstr, sizeof(addrstr));
}

