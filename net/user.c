// net-user part of mtr085

#include <errno.h>
#include <arpa/inet.h>

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "log.h"

#include "raw.h"
#include "aux.h"
#include "nls.h"
#include "netmisc.h"
#include "display.h" // IWYU pragma: keep

// global
int usersock = -1;

//
static int usersock4_icmp = -1;
//static int usersock4_udp  = -1; // not yet
#ifdef ENABLE_IPV6
static int usersock6_icmp = -1;
//static int usersock6_udp  = -1; // not yet
#endif

// Send packet via ICMP socket for hop 'at'
static bool usersend_icmp(int at) {
  uint8_t packet[MAXPACKET];
  memset(packet, bitpattern, sizeof(packet));
  //
  _icmphdr *icmp = (_icmphdr *)packet;
  uint16_t pktsize = sizeof(_icmphdr) + payloadsize;
  int ttl = at + 1, echotype = 0, salen = 0;
  switch (af) {
    case AF_INET:  // TODO: set it once (or when it's changed)
      if (!settosttl4(usersock, ttl))
        return false;
      echotype = ICMP_ECHO;
      salen = sizeof(struct sockaddr_in);
    break;
#ifdef ENABLE_IPV6
    case AF_INET6: // TODO: set it once (or when it's changed)
      if (!settosttl6(usersock, ttl))
        return false;
      echotype = ICMP6_ECHO_REQUEST;
      salen = sizeof(struct sockaddr_in6);
      break;
#endif
    default:
      FAIL_POSTPONE(EAFNOSUPPORT, af);
  }
  int seq = new_sequence(at);
  fill_icmph(echotype, 0, seq, icmp);
  bool okay = save_curr_ts(seq);
  if (okay) {
    if (sendto(usersock, packet, pktsize, 0, &rsa.sa, salen) < 0) {
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
ping_fn ping_icmp = usersend_icmp;
ping_fn ping_udp  = NULL/*not yet*/;

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
bool open_sock46(void) {
  usersock4_icmp = open_socket_n_recverr(AF_INET, IPPROTO_ICMP, IPPROTO_IP, IP_RECVERR);
  if (usersock4_icmp < 0)
    WARNXT("usersock4-icmp: %s", NOSOCK_ERR);
  else {
    sum_sock[0]++; /*summ*/
#ifdef ENABLE_IPV6
    usersock6_icmp = open_socket_n_recverr(AF_INET6, IPPROTO_ICMPV6, IPPROTO_IPV6, IPV6_RECVERR);
    if (usersock6_icmp < 0)
      WARNXT("usersock6-icmp: %s", NOSOCK_ERR);
    else
      sum_sock[0]++; /*summ*/
#endif
  }
  LOGMSG("usersock4_icmp=%d", usersock4_icmp);
#ifdef ENABLE_IPV6
  LOGMSG("usersock6_icmp=%d", usersock6_icmp);
#endif
  // mandatory ip4 socket, optional ip6 socket
  return (usersock4_icmp >= 0);
}

void close_sock46(void) {
  FD_CLOSE(usersock4_icmp);
//  FD_CLOSE(usersock4_udp);
#ifdef ENABLE_IPV6
  FD_CLOSE(usersock6_icmp);
//  FD_CLOSE(usersock6_udp);
#endif
  usersock = -1;
}

bool sock4_ready(int type) {
  bool ready = false;
  switch (type) {
    case IPPROTO_ICMP:
      ready = (usersock4_icmp >= 0);
      break;
//    case IPPROTO_UDP:
//      ready = (usersock4_udp >= 0);
//      break;
    default: break;
  }
  return ready;
}

#ifdef ENABLE_IPV6
bool sock6_ready(int type) {
  bool ready = false;
  switch (type) {
    case IPPROTO_ICMP:
      ready = (usersock6_icmp >= 0);
      break;
//    case IPPROTO_UDP:
//      ready = (usersock6_udp >= 0);
//      break;
    default: break;
  }
  return ready;
}
#endif

void set_sock4(void) {
  usersock =
    (proto == IPPROTO_ICMP) ? usersock4_icmp :
//    (proto == IPPROTO_UDP)  ? usersock4_udp  :
    -1;
}

#ifdef ENABLE_IPV6
void set_sock6(void) {
  usersock =
    (usersock == IPPROTO_ICMP) ? usersock6_icmp :
//    (usersock == IPPROTO_UDP)  ? usersock6_udp  :
    -1;
}
#endif

