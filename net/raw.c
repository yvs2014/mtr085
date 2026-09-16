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

#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "log.h"

#ifdef LIBCAP
#include <sys/capability.h>
#endif

//#ifdef HAVE_NETDB_H
//#include <netdb.h>
//#endif

#include "raw.h"
#include "netmisc.h"
#include "aux.h"     // IWYU pragma: keep
#include "display.h" // IWYU pragma: keep
#ifdef LOGMOD
#include "nls.h"
#endif

// global vars
int recvsock = -1;
int sendsock = -1;

//
static int recvsock4      = -1;
static int sendsock4_icmp = -1;
static int sendsock4_udp  = -1;
#ifdef ENABLE_IPV6
static int recvsock6      = -1;
static int sendsock6_icmp = -1;
static int sendsock6_udp  = -1;
#endif

//

static uint16_t sum1616(const uint16_t *data, uint len, uint sum) {
  for (; len; len--)
    sum += *data++;
  while (sum >> 16)
    sum = (sum >> 16) + (sum & 0xffff);
  return ~sum;
}

// Send DGRAM packet via RAW socket for hop 'at'
static bool rawsend_icmp_udp(int at) {
  int ttl = at + 1;
  if (!(netkit.set_ttl && netkit.set_ttl(sendsock, ttl)))
    return false;
  uint8_t packet[MAXPACKET];
  memset(packet, bitpattern, sizeof(packet));
  uint16_t pktsize = 8/*icmp,udp header*/ + payloadsize;
  int seq = new_sequence(at);
  switch (proto) {
    case IPPROTO_ICMP:
      fill_icmph(netkit.ping, pid16, seq, (_icmphdr*)packet);
      ((_icmphdr *)packet)->sum =
        sum1616((uint16_t *)packet, pktsize / 2, (pktsize % 2) ? bitpattern : 0);
      break;
    case IPPROTO_UDP:
      fill_udph(seq, (_udphdr*)packet, pktsize);
      if ((af == AF_INET6) && !set_opt_ck6(sendsock))
        return false;
      break;
    default:
      FAIL_POSTPONE(EPROTONOSUPPORT, proto);
  }
  //
  bool okay = save_curr_ts(seq);
  if (okay) {
    if (sendto(sendsock, packet, pktsize, 0, SA(&rsa), netkit.salen) < 0) {
      int rc = errno;
      char str[MAX_ADDRSTRLEN] = {0};
      const char *dst = inet_ntop(af, remote_ipaddr, str, sizeof(str));
      errno = rc;
      FAIL_WITH_WARN(sendsock, "sendto(%s)", dst ? dst : "");
    }
    /*summ*/ net_queries[QR_SUM]++; if (proto == IPPROTO_ICMP) net_queries[QR_ICMP]++; else net_queries[QR_UDP]++;
  }
  return okay;
}
ping_fn ping_icmp = rawsend_icmp_udp;
ping_fn ping_udp  = rawsend_icmp_udp;

#ifdef LIBCAP
static void set_rawcap_flag(cap_flag_value_t onoff) {
  cap_t curr = cap_get_proc();
  if (curr) {
    cap_flag_value_t perm = onoff;
    if (cap_get_flag(curr, CAP_NET_RAW, CAP_PERMITTED, &perm) < 0)
      warn("cap_get_flag(%s, raw)", "PERMITTED");
    else if (perm != CAP_CLEAR) { // permitted to set/clear
      cap_value_t raw = CAP_NET_RAW;
      if (cap_set_flag(curr, CAP_EFFECTIVE, 1, &raw, onoff) < 0)
        warn("cap_set_flag(%s, raw, %d)", "EFFECTIVE", onoff);
      else if (cap_set_proc(curr) < 0)
        warn("cap_set_proc(%s, raw, %d", "EFFECTIVE", onoff);
    }
    cap_free(curr);
  } else
    warn("cap_get_proc()");
}
#define RAWCAP_ON  set_rawcap_flag(CAP_SET)
#define RAWCAP_OFF set_rawcap_flag(CAP_CLEAR)
#else
#define RAWCAP_ON
#define RAWCAP_OFF
#endif

static int rawsock(int domain, int type, int proto, const char *what) {
  RAWCAP_ON;
  int sock = socket(domain, type, proto);
  int keep = errno;
  RAWCAP_OFF;
  if (sock < 0) {
    errno = keep;
    warn("%s", what);
    close_all_socks();
  } else
    /*summ*/ sum_sock[0]++;
  return sock;
}

//

bool open_all_socks(void) {
  // mandatory ipv4
  recvsock4 = rawsock(AF_INET, SOCK_RAW, IPPROTO_ICMP, "icmp-raw-recvsock");
  if (recvsock4 < 0)
    return false;
  /*summ*/ sum_sock[0]++;
  sendsock4_icmp = rawsock(AF_INET, SOCK_RAW, IPPROTO_ICMP, "icmp-raw-sendsock");
  if (sendsock4_icmp < 0)
    return false;
  /*summ*/ sum_sock[0]++;
  sendsock4_udp = rawsock(AF_INET, SOCK_RAW, IPPROTO_UDP, "udp-raw-sendsock");
  if (sendsock4_udp < 0)
    return false;
  /*summ*/ sum_sock[0]++;
  LOGMSG("sendsock4_icmp=%d sendsock4_udp=%d", sendsock4_icmp, sendsock4_udp);
#ifdef ENABLE_IPV6
  // optional ipv6
  RAWCAP_ON;
  recvsock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (recvsock6 >= 0)
    sum_sock[0]++; /*summ*/
  else
    LOGMSG("recvsock6: %s", NOSOCK_ERR);
  sendsock6_icmp = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (sendsock6_icmp >= 0)
    sum_sock[0]++; /*summ*/
  else
    LOGMSG("sendsock6_icmp: %s", NOSOCK_ERR);
  sendsock6_udp = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
  if (sendsock6_udp >= 0)
    sum_sock[0]++; /*summ*/
  else
    LOGMSG("sendsock6_udp: %s", NOSOCK_ERR);
  RAWCAP_OFF;
  LOGMSG("sendsock6_icmp=%d sendsock6_udp=%d", sendsock6_icmp, sendsock6_udp);
#endif
  return true;
}

void close_all_socks(void) {
  FD_CLOSE(recvsock4);
  FD_CLOSE(sendsock4_icmp);
  FD_CLOSE(sendsock4_udp);
#ifdef ENABLE_IPV6
  FD_CLOSE(recvsock6);
  FD_CLOSE(sendsock6_icmp);
  FD_CLOSE(sendsock6_udp);
#endif
  sendsock = recvsock = -1;
}

bool sock4_ready(int type) {
  bool ready = (recvsock4 >= 0);
  if (ready) switch (type) {
    case IPPROTO_ICMP:
      ready = (sendsock4_icmp >= 0);
      break;
   case IPPROTO_UDP:
      ready = (sendsock4_udp >= 0);
      break;
    default: break;
  }
  return ready;
}

#ifdef ENABLE_IPV6
bool sock6_ready(int type) {
  bool ready = (recvsock6 >= 0);
  if (ready) switch (type) {
    case IPPROTO_ICMP:
      ready = (sendsock6_icmp >= 0);
      break;
   case IPPROTO_UDP:
      ready = (sendsock6_udp >= 0);
      break;
    default: break;
  }
  return ready;
}
#endif

void setsock_qos4(void) {
  if (recvsock >= 0)
    set_tos4(recvsock);
  if (sendsock >= 0)
    set_tos4(sendsock);
}
//
void set_sock4(void) {
  recvsock = recvsock4;
  sendsock =
    (proto == IPPROTO_ICMP) ? sendsock4_icmp :
    (proto == IPPROTO_UDP)  ? sendsock4_udp  :
    -1;
  setsock_qos4();
}
//
#ifdef ENABLE_IPV6
void setsock_qos6(void) {
  if (recvsock >= 0)
    set_tos6(recvsock);
  if (sendsock >= 0)
    set_tos6(sendsock);
}
//
void set_sock6(void) {
  recvsock = recvsock6;
  sendsock =
    (proto == IPPROTO_ICMP) ? sendsock6_icmp :
    (proto == IPPROTO_UDP)  ? sendsock6_udp  :
    -1;
  setsock_qos6();
}
#endif

int get_valid_seq(const _icmphdr *icmp) { // NONNULL(1)
  uint16_t id  = ntohs(icmp->id);
  int seq = (id == pid16) ? ntohs(icmp->seq) : -1;
#ifdef LOGMOD
  if (seq < 0)
    LOGMSG("icmp(myid=%u): got unknown id=%u (type=%u seq=%u)",
      pid16, id, (icmp)->type, seq);
#endif
  return seq;
}

