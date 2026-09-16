#ifndef NETMISC
#define NETMISC

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifdef WITH_MPLS
#define LOGMSG_ICMP LOGMSG("icmp seq=%d type=%d mpls=%d", seq, icmp->type, mplson)
#define LOGMSG_UDP  LOGMSG("udp seq=%d id=%d mpls=%d", seq, portpid, mplson)
#define LOGMSG_TCP  LOGMSG("tcp seq=%d mpls=%d", seq, mplson);
#define MPLS_LIKE_TEST do { mplson = mplslike(size, data - packet); } while (0)
#else
#define LOGMSG_ICMP LOGMSG("icmp seq=%d type=%d", seq, icmp->type)
#define LOGMSG_UDP  LOGMSG("udp seq=%d id=%d", seq, portpid)
#define LOGMSG_TCP  LOGMSG("tcp seq=%d", seq);
#define MPLS_LIKE_TEST NOOP
#endif

#define LO_UDPPORT 33433 // start from LO_UDPPORT+1
#define UDPPORTS      90 // go thru udp:33434-33523 acl

enum IPV6_ENDIS {IPV6_UNDEF = -1, IPV6_DISABLED = 0, IPV6_ENABLED = 1};
enum {RE_PONG, RE_EXCEED, RE_UNREACH}; // reasons of a pong response

enum {QR_SUM = 0/*sure*/, QR_ICMP, QR_UDP, QR_TCP, QR_MAX};
extern ulong net_queries[QR_MAX]; // number of queries (sum, icmp, udp, tcp)
extern ulong net_replies[QR_MAX]; // number of replies (sum, icmp, udp, tcp)

typedef struct netkit {
  bool ip6;
  socklen_t salen;
  uint ipicmphsz;
  uint8_t ping, pong, exceed, unreach;
  bool (*set_ttl)(int sock, int ttl);
} netkit_t;
extern netkit_t netkit;

int net_stat_sa(uint port, const struct sockaddr *sa, // NONNULL(2, 3)
  const struct timespec *recv_at, int reason, const void *mpls);
#ifdef WITH_MPLS
bool mplslike(ssize_t psize, ssize_t hsize);
void* decodempls(const uint8_t *data, int size); // NONNULL(1)
#endif

#endif
