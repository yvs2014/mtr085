// net-exterr part of mtr085

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
#include <linux/errqueue.h>

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "log.h"

#include "exterr.h"
#include "attr.h"

#define EXCEED_O_UNREACH(type) ( \
  ((type) == eeset.exceed/*ICMP_TIME_EXCEEDED,ICMPV6_TIME_EXCEED*/)  \
   || \
  ((type) == eeset.unreach/*ICMP_DEST_UNREACH,ICMPV6_DEST_UNREACH*/) \
)

typedef struct eeset {
  bool ip6;
  socklen_t salen;
  uint8_t addrlen;
  uint8_t orig, code, exceed, unreach;
} eeset_t;

static eeset_t eeset;

static void ee_handler(const struct sock_extended_err *e, const struct msghdr *msg,
  const struct timespec *recv_at, size_t size UNUSED) NONNULL(1, 2, 3);
static void ee_handler(const struct sock_extended_err *e, const struct msghdr *msg,
  const struct timespec *recv_at, size_t size UNUSED)
{
  LOGMSG("ee: errno=%u origin=%u type=%u code=%u info=%u",
    e->ee_errno, e->ee_origin, e->ee_type, e->ee_code, e->ee_info);
  if ((e->ee_origin == eeset.orig) && (e->ee_code  == eeset.code) && EXCEED_O_UNREACH(e->ee_type)) {
    struct iovec *iov = msg->msg_iov;
    struct sockaddr *from = SO_EE_OFFENDER(e);
    bool af_okay =
#ifdef ENABLE_IPV6
      eeset.ip6 ? (((struct sockaddr_in6 *)from)->sin6_family == AF_INET6) :
#endif
                  (((struct sockaddr_in  *)from)->sin_family  == AF_INET);
    if (af_okay && iov && (iov->iov_len >= sizeof(struct icmphdr))) {
      struct icmphdr *icmp = (struct icmphdr*)iov->iov_base;
      uint16_t seq = __be16_to_cpu(icmp->un.echo.sequence);
#ifdef WITH_MPLS
      bool mplson = mplslike(size, 0);
#endif
      int reason = (e->ee_type == eeset.exceed) ? RE_EXCEED : RE_UNREACH;
      LOGMSG_ICMP;
      net_stat_sa(seq, from, recv_at, reason,
#ifdef WITH_MPLS
        mplson ? decodempls((uint8_t*)icmp, size) :
#endif
        NULL);
      /*summ*/ net_replies[QR_ICMP]++;
      /*summ*/ net_replies[QR_SUM]++;
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
      eeset.ip6 ? (void*)&((struct sockaddr_in6 *)msg->msg_name)->sin6_addr :
#endif
                  (void*)&((struct sockaddr_in  *)msg->msg_name)->sin_addr;
    if (!memcmp(addr, remote, eeset.addrlen)) // be sure target-address is correct
      for (struct cmsghdr *c = CMSG_FIRSTHDR(msg); c; c = CMSG_NXTHDR(msg, c))
        if ((c->cmsg_level == IPPROTO_IP) && (c->cmsg_type == IP_RECVERR)) {
          const struct sock_extended_err *e = (struct sock_extended_err *)CMSG_DATA(c);
          if (e)
            ee_handler(e, msg, recv_at, rc);
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
      .msg_namelen    = eeset.salen,
      .msg_iov        = &iov,
      .msg_iovlen     = 1,
      .msg_control    = cmsg,
      .msg_controllen = sizeof(cmsg),
    };
    if (recverrmsg(sock, &msg, recv_at, remote) < 0)
      break;
  };
}

void ee_settings(enum IPV6_ENDIS ip6) {
  if (ip6 == IPV6_ENABLED) {
#ifdef ENABLE_IPV6
    eeset = (eeset_t){
      .ip6     = true,
      .salen   = sizeof(struct sockaddr_in6),
      .addrlen = sizeof(struct in6_addr),
      .orig    = SO_EE_ORIGIN_ICMP6,
      .code    = ICMPV6_EXC_HOPLIMIT, /*the same ICMPV6_NOROUTE value*/
      .exceed  = ICMPV6_TIME_EXCEED,
      .unreach = ICMPV6_DEST_UNREACH,
    };
#endif
  } else {
    eeset = (eeset_t){
      .ip6     = false,
      .salen   = sizeof(struct sockaddr_in),
      .addrlen = sizeof(struct in_addr),
      .orig    = SO_EE_ORIGIN_ICMP,
      .code    = ICMP_EXC_TTL, /*the same ICMP_NET_UNREACH value*/
      .exceed  = ICMP_TIME_EXCEEDED,
      .unreach = ICMP_DEST_UNREACH,
    };
  }
  LOGMSG("eeset%c: salen=%u orig=%d code=%u exceed=%u unreach=%u", ip6 ? '6' : '4',
    eeset.salen, eeset.orig, eeset.code, eeset.exceed, eeset.unreach);
}

