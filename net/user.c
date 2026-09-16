// net-user part of mtr085

#include <errno.h>
#include <arpa/inet.h>

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "log.h" // IWYU pragma: keep

#include "user.h"
#include "aux.h"
#include "nls.h"
#include "netmisc.h"
#include "display.h" // IWYU pragma: keep

// global
int usersock = -1;

//
static int usersock4_icmp = -1;
static int usersock4_udp  = -1;
#ifdef ENABLE_IPV6
static int usersock6_icmp = -1;
static int usersock6_udp  = -1;
#endif

static bool savets_n_sendto(int seq, const struct sockaddr *sa,
  uint16_t len, const uint8_t packet[len]) NONNULL(2, 4);
static bool savets_n_sendto(int seq, const struct sockaddr *sa,
  uint16_t len, const uint8_t packet[len])
{
  bool okay = save_curr_ts(seq);
  if (okay) {
    if (sendto(usersock, packet, len, MSG_DONTWAIT, sa, netkit.salen) < 0) {
      int rc = errno;
      switch (rc) {
        case EAGAIN:
        case ENOMEM:
        case ENOBUFS: { // fail
          char str[MAX_ADDRSTRLEN] = {0};
          const char *dst = inet_ntop(af, remote_ipaddr, str, sizeof(str));
          errno = rc;
          FAIL_WITH_WARN(usersock, "sendto(%s)", dst ? dst : "");
        } break;
        default: // read extended err later
          break;
      }
    }
    /*summ*/ net_queries[QR_SUM]++; net_queries[QR_ICMP]++;
  }
  return okay;
}

// Send packet via ICMP socket for hop 'at'
static bool usersend_icmp(int at) {
  bool okay = (netkit.set_ttl && netkit.set_ttl(usersock, at + 1));
  if (okay) {
    uint8_t packet[MAXPACKET];
    memset(packet, bitpattern, sizeof(packet));
    int seq = new_sequence(at);
    fill_icmph(netkit.ping, 0, seq, (_icmphdr*)packet);
    okay = savets_n_sendto(seq, SA(&rsa), sizeof(_icmphdr) + payloadsize, packet);
  }
  return okay;
}

// Send packet via UDP socket for hop 'at'
static bool usersend_udp(int at) {
  bool okay = (netkit.set_ttl && netkit.set_ttl(usersock, at + 1));
  if (okay) {
    uint8_t packet[MAXPACKET];
    memset(packet, bitpattern, sizeof(packet));
    int seq = new_sequence(at);
    struct sockaddr_storage ss = rsa;
    uint16_t port = htons(LO_UDPPORT + seq);
#ifdef ENABLE_IPV6
    if (af == AF_INET6)
      SPORT6(&ss) = port;
    else
#endif
    { SPORT4(&ss) = port; }
    okay = savets_n_sendto(seq, SA(&ss), sizeof(_udphdr) + payloadsize, packet);
    LOGMSG("seq=%d port=%u", seq, port);
  }
  return okay;
}

ping_fn ping_icmp = usersend_icmp;
ping_fn ping_udp  = usersend_udp;

//
static int open_socket_n_recverr(int domain, int proto, int level, int optname) {
  int fd = socket(domain, SOCK_DGRAM, proto);
  if (fd < 0)
    WARNT("socket(domain=%d, type=%d, proto=%d)", domain, SOCK_DGRAM, proto);
  else {
    int opt = 1;
    if (setsockopt(fd, level, optname, &opt, sizeof(opt)) < 0) {
      WARNT("setsockopt(level=%d, optname=%d)", level, optname);
      close(fd);
      fd = -1;
    }
  }
  return fd;
}
//
static int opensockprot(const char *desc, int domain, int proto, int level, int optname) {
  int sock = open_socket_n_recverr(domain, proto, level, optname);
  if (sock < 0)
    WARNXT("%d: %s", desc ? desc : "", NOSOCK_ERR);
  else {
    usersock = sock;
    sum_sock[0]++; /*summ*/
  }
  return sock;
}
//
#define GETSOCKPROT(sock, desc, dom, prot, level, opt) do {     \
  FD_CLOSE(sock);                                               \
  (sock) = opensockprot((desc), (dom), (prot), (level), (opt)); \
} while (0)
#define GETSOCKICMP4 GETSOCKPROT(usersock4_icmp, "usersock4-icmp", AF_INET,  IPPROTO_ICMP,   IPPROTO_IP,   IP_RECVERR)
#define GETSOCKUDP4  GETSOCKPROT(usersock4_udp,  "usersock4-udp",  AF_INET,  IPPROTO_UDP,    IPPROTO_IP,   IP_RECVERR)
#define GETSOCKICMP6 GETSOCKPROT(usersock6_icmp, "usersock6-icmp", AF_INET6, IPPROTO_ICMPV6, IPPROTO_IPV6, IPV6_RECVERR)
#define GETSOCKUDP6  GETSOCKPROT(usersock6_udp,  "usersock6-udp",  AF_INET6, IPPROTO_UDP,    IPPROTO_IPV6, IPV6_RECVERR)
//
bool open_sock(int type) {
#ifdef ENABLE_IPV6
  if (af == AF_INET6) {
    if      (type == IPPROTO_ICMP)
      GETSOCKICMP6;
    else if (type == IPPROTO_UDP)
      GETSOCKUDP6;
    setsock_qos6();
  } else
#endif
  {
    if      (type == IPPROTO_ICMP)
      GETSOCKICMP4;
    else if (type == IPPROTO_UDP)
      GETSOCKUDP4;
    setsock_qos4();
  }
  LOGMSG("usersock4_icmp=%d usersock4_udp=%d", usersock4_icmp, usersock4_udp);
#ifdef ENABLE_IPV6
  LOGMSG("usersock6_icmp=%d usersock6_udp=%d", usersock6_icmp, usersock6_udp);
#endif
  LOGMSG("usersock=%d SENDSOCK=%d RECVSOCK=%d", usersock, SENDSOCK, RECVSOCK);
  return (usersock >= 0);
}

void close_all_socks(void) {
#ifdef ENABLE_IPV6
  FD_CLOSE(usersock6_icmp);
  FD_CLOSE(usersock6_udp);
#endif
  FD_CLOSE(usersock4_icmp);
  FD_CLOSE(usersock4_udp);
  usersock = -1;
}

bool sock4_ready(int type) {
  bool ready =
    (type == IPPROTO_ICMP) ? (usersock4_icmp >= 0) :
    (type == IPPROTO_UDP)  ? (usersock4_udp  >= 0) :
    false;
  return ready ? ready : open_sock(type);
}

#ifdef ENABLE_IPV6
bool sock6_ready(int type) {
  bool ready =
    (type == IPPROTO_ICMP) ? (usersock6_icmp >= 0) :
    (type == IPPROTO_UDP)  ? (usersock6_udp  >= 0) :
    false;
  return ready ? ready : open_sock(type);
}
#endif

inline void setsock_qos4(void) {
  if (usersock >= 0)
    set_tos4(usersock);
}
//
void set_sock4(void) {
  usersock =
    (proto == IPPROTO_ICMP) ? usersock4_icmp :
    (proto == IPPROTO_UDP)  ? usersock4_udp  :
    -1;
  setsock_qos4();
}
//
#ifdef ENABLE_IPV6
inline void setsock_qos6(void) {
  if (usersock >= 0)
    set_tos6(usersock);
}
//
void set_sock6(void) {
  usersock =
    (usersock == IPPROTO_ICMP) ? usersock6_icmp :
    (usersock == IPPROTO_UDP)  ? usersock6_udp  :
    -1;
  setsock_qos6();
}
#endif

