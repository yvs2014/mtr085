// linux specific (sock_extended_err) net part of mtr085

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/icmp.h>
#ifdef ENABLE_IPV6
#include <linux/in6.h>
#include <linux/icmpv6.h>
#endif
#include <linux/udp.h>
#include <linux/errqueue.h>

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "log.h"

#include "linux-exterr.h"
#include "attr.h"

#define EXCEED_O_UNREACH(type) ( \
  ((type) == netkit.exceed/*ICMP_TIME_EXCEEDED,ICMPV6_TIME_EXCEED*/)  \
   || \
  ((type) == netkit.unreach/*ICMP_DEST_UNREACH,ICMPV6_DEST_UNREACH*/) \
)

#ifdef WITH_MPLS
#define LOGMSG_SEQM LOGMSG("seq=%d mpls=%d", seq, mplson)
#else
#define LOGMSG_SEQM LOGMSG("seq=%d", seq)
#endif

typedef struct eekit {
  sa_family_t af;
  uint8_t addrlen;
  uint8_t orig, icmpcode, udpcode;
  void (*handler)(const struct sock_extended_err *e, const struct msghdr *msg,
    const struct timespec *recv_at, uint len);
  int elevel, etype; /*cmsg_level, cmsg_type*/
  uint16_t maxseq;
} eekit_t;

static eekit_t eekit;

static void ee_handler_icmp(const struct sock_extended_err *e, const struct msghdr *msg,
  const struct timespec *recv_at, uint recv_size UNUSED) NONNULL(1, 2, 3);
static void ee_handler_icmp(const struct sock_extended_err *e, const struct msghdr *msg,
  const struct timespec *recv_at, uint recv_size UNUSED)
{
  LOGMSG("ee: errno=%u origin=%u type=%u code=%u info=%u",
    e->ee_errno, e->ee_origin, e->ee_type, e->ee_code, e->ee_info);
  if ((e->ee_origin == eekit.orig)
      && (e->ee_code == eekit.icmpcode)
      && EXCEED_O_UNREACH(e->ee_type))
  {
    struct sockaddr *from = SO_EE_OFFENDER(e);
    if (from && (from->sa_family == eekit.af)) {
      struct iovec *iov = msg->msg_iov;
      if (iov && (iov->iov_len >= sizeof(struct icmphdr))) {
        int reason = (e->ee_type == netkit.exceed) ? RE_EXCEED : RE_UNREACH;
        struct icmphdr *icmp = (struct icmphdr*)iov->iov_base;
        uint16_t seq = __be16_to_cpu(icmp->un.echo.sequence);
//        /* not yet, not tested*/
//#ifdef WITH_MPLS
//        bool mplson = mplslike(recv_size, 0);
//#endif
//        LOGMSG_ICMP;
        LOGMSG("icmp seq=%d type=%d", seq, icmp->type);
        net_stat_sa(seq, from, recv_at, reason,
//#ifdef WITH_MPLS
//          mplson ? decodempls((uint8_t*)icmp, size) :
//#endif
          NULL);
        /*summ*/ net_replies[QR_ICMP]++;
        /*summ*/ net_replies[QR_SUM]++;
      }
    }
  }
}

static void ee_handler_udp(const struct sock_extended_err *e, const struct msghdr *msg,
  const struct timespec *recv_at, uint recv_size UNUSED) NONNULL(1, 2, 3);
static void ee_handler_udp(const struct sock_extended_err *e, const struct msghdr *msg,
  const struct timespec *recv_at, uint recv_size UNUSED)
{
  LOGMSG("ee: errno=%u origin=%u type=%u code=%u info=%u",
    e->ee_errno, e->ee_origin, e->ee_type, e->ee_code, e->ee_info);
  if ((e->ee_origin == eekit.orig)
      && ((e->ee_code == eekit.icmpcode) || (e->ee_code == eekit.udpcode))
      && EXCEED_O_UNREACH(e->ee_type))
  {
    struct sockaddr *from = SO_EE_OFFENDER(e);
    if (from && (from->sa_family == eekit.af)) {
      uint16_t dport =
#ifdef ENABLE_IPV6
        netkit.ip6 ? ((struct sockaddr_in6 *)msg->msg_name)->sin6_port :
#endif
                     ((struct sockaddr_in  *)msg->msg_name)->sin_port;
      uint16_t port = __be16_to_cpu(dport);
      if (port >= LO_UDPPORT) {
        uint16_t seq = port - LO_UDPPORT;
        if (seq < eekit.maxseq) {
          int reason = (e->ee_type == netkit.exceed) ? RE_EXCEED : RE_UNREACH;
          net_stat_sa(seq, from, recv_at, reason, NULL);
          /*summ*/ net_replies[QR_UDP]++;
          /*summ*/ net_replies[QR_SUM]++;
        }
      }
    }
  }
}

static int recverrmsg(int sock, struct msghdr *msg,
  const struct timespec *recv_at, const void *remote) NONNULL(2, 3, 4);
static int recverrmsg(int sock, struct msghdr *msg,
  const struct timespec *recv_at, const void *remote)
{
  ssize_t rc = recvmsg(sock, msg, MSG_ERRQUEUE | MSG_DONTWAIT);
  if (rc >= 0) {
    void *addr =
#ifdef ENABLE_IPV6
      netkit.ip6 ? (void*)&((struct sockaddr_in6 *)msg->msg_name)->sin6_addr :
#endif
                   (void*)&((struct sockaddr_in  *)msg->msg_name)->sin_addr;
    if (!memcmp(addr, remote, eekit.addrlen)) // be sure target-address is correct
      for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c))
        if ((c->cmsg_level == eekit.elevel) && (c->cmsg_type == eekit.etype)) {
          const struct sock_extended_err *e = (struct sock_extended_err *)CMSG_DATA(c);
          if (e && eekit.handler)
            eekit.handler(e, msg, recv_at, rc);
        }
  }
  return rc;
}

//

#define GETERRATONCE 10

void sockrecverr(int sock, const struct timespec *recv_at, const void *remote) { // NONNULL(2, 3)
  for (uint i = 0; i < GETERRATONCE; i++) {
    char cmsg[CMSG_SPACE(sizeof(struct sock_extended_err)) + sizeof(struct sockaddr_storage)] = {0};
    char buff[1500]   = {0}; // either max-packet-size(1500) or recommended max--datagram-size(576)
    struct iovec iov  = {
      .iov_base = &buff,
      .iov_len  = sizeof(buff),
    };
    struct sockaddr_storage sa = {0};
    struct msghdr msg = {
      .msg_name       = &sa,
      .msg_namelen    = netkit.salen,
      .msg_iov        = &iov,
      .msg_iovlen     = 1,
      .msg_control    = cmsg,
      .msg_controllen = sizeof(cmsg),
    };
    if (recverrmsg(sock, &msg, recv_at, remote) < 0)
      break;
  };
}

void ee_settings(enum IPV6_ENDIS ip6, int proto, uint maxseq) {
  if (ip6 == IPV6_ENABLED) {
#ifdef ENABLE_IPV6
    eekit = (eekit_t){
      .af       = AF_INET6,
      .elevel   = IPPROTO_IPV6,
      .etype    = IPV6_RECVERR,
      .addrlen  = sizeof(struct in6_addr),
      .orig     = SO_EE_ORIGIN_ICMP6,
      .icmpcode = ICMPV6_EXC_HOPLIMIT, /*the same ICMPV6_NOROUTE value*/
      .udpcode  = ICMPV6_PORT_UNREACH,
    };
#endif
  } else {
    eekit = (eekit_t){
      .af       = AF_INET,
      .elevel   = IPPROTO_IP,
      .etype    = IP_RECVERR,
      .addrlen  = sizeof(struct in_addr),
      .orig     = SO_EE_ORIGIN_ICMP,
      .icmpcode = ICMP_EXC_TTL, /*the same ICMP_NET_UNREACH value*/
      .udpcode  = ICMP_PORT_UNREACH,
    };
  }
  eekit.handler = (proto == IPPROTO_ICMP) ? ee_handler_icmp : ee_handler_udp;
  eekit.maxseq  = maxseq;
  LOGMSG("eekit%c af=%d proto=%d maxseq=%u: orig=%d icmpcode=%u idpcode=%u",
    ip6 == IPV6_ENABLED ? '6' : '4', eekit.af, proto, eekit.maxseq,
    eekit.orig, eekit.icmpcode, eekit.udpcode);
}

