
// net-common part of mtr085

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "log.h"

#include "netcommon.h"
#include "aux.h"
#include "nls.h"     // IWYU pragma: keep
#include "display.h" // IWYU pragma: keep
#include "netmisc.h"
#ifdef USE_RAW
#include "polling.h"
#endif

// global
//
struct sockaddr_storage lsa, rsa; // local and remote sockaddr
t_ipaddr *remote_ipaddr = (t_ipaddr*)&SADDR4(&rsa); // ip4 by default

hop_t hop[MAXHOST];
struct sequence seqlist[MAXSEQ];

uint8_t bitpattern;
uint16_t payloadsize = PAYLOAD_SIZE;
int portpid;

ulong net_queries[QR_MAX];  // number of queries (sum, icmp, udp, tcp)
ulong net_replies[QR_MAX];  // number of replies (sum, icmp, udp, tcp)

char strerr_txt[NAMELEN];     // any target
char tgterr_txt[NAMELEN];     // current target
char logerr_txt[NAMELEN * 2]; // $func: $tgterr

const t_ipaddr unspec_addr; // 0
#define TCP_DEFAULT_PORT 80

//

static void net_warn(const char *prefix) NONNULL(1);
static void net_warn(const char *prefix) {
  char* str = tgterr_txt[0] ? tgterr_txt : "Unknown error";
  warnx("%s: %s", prefix, str);
  snprinte(logerr_txt, sizeof(logerr_txt), "%s: %s", prefix, str);
  LOGMSG("%s: %s", prefix, str);
}

//

bool addr4exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in_addr)) ? true : false; }
bool addr4equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in_addr)) ? false : true; }
void* addr4copy(void *dst, const void *src) { return memcpy(dst, src, sizeof(struct in_addr)); }
#ifdef ENABLE_IPV6
bool addr6exist(const void *a) { return memcmp(a, &unspec_addr, sizeof(struct in6_addr)) ? true : false; }
bool addr6equal(const void *a, const void *b) { return memcmp(a, b, sizeof(struct in6_addr)) ? false : true; }
void* addr6copy(void *dst, const void *src) { return memcpy(dst, src, sizeof(struct in6_addr)); }
#endif

//
// ip4: addr4xxx (by default)
// ip6: addr6xxx
bool  (*addr_exist)(const void *a) NONNULL(1) = addr4exist; // true unless 0
bool  (*addr_equal)(const void *a, const void *b) NONNULL(1, 2) = addr4equal;
void* (*addr_copy)(void *dst, const void *src) NONNULL(1, 2) = addr4copy;

const char* rstrerror(int rc) {
  snprinte(strerr_txt, sizeof(strerr_txt), "%s", strerror(rc));
  snprinte(tgterr_txt, sizeof(tgterr_txt), "%s", strerror(rc));
  return tgterr_txt;
}

void keep_error(int rc, const char *prefix) { // NONNULL(2)
  rstrerror(rc);
  net_warn(prefix);
}

int new_sequence(int at) {
  static int next_seq;
  int seq = next_seq++;
  if (next_seq >= ((proto == IPPROTO_UDP) ? UDPPORTS : MAXSEQ))
    next_seq = 0;
  save_sequence(seq, at);
  return seq;
}

void save_sequence(int seq, int at) {
  LOGMSG("seq=%d at=%d", seq, at);
  seqlist[seq].at = at;
  seqlist[seq].transit = true;
  if (hop[at].transit)
    hop[at].up = false; // if previous packet is in transit too, then assume it's down
  hop[at].transit = true;
  hop[at].sent++;
#ifdef TUIMODE
  seqlist[seq].saved_seq = hop[at].sent;
  if (hop[at].saved[SAVED_PINGS - 1] != CT_UNSENT) {
    for (int at = 0; at < MAXHOST; at++) {
      memmove(hop[at].saved, hop[at].saved + 1, (SAVED_PINGS - 1) * sizeof(int));
      hop[at].saved[SAVED_PINGS - 1] = CT_UNSENT;
      hop[at].saved_seq_offset += 1;
    }
  }
  hop[at].saved[SAVED_PINGS - 1] = CT_UNKN;
#endif
}

bool save_curr_ts(int seq) {
  int rc = clock_gettime(CLOCK_MONOTONIC, &seqlist[seq].time);
  if (rc)
    keep_error(errno, __func__);
  return (rc == 0);
}

#define NET_SETTTL(PROTO_VERSION, TTL_TYPE) do {                        \
  if (setsockopt(sock, PROTO_VERSION, TTL_TYPE, &ttl, sizeof(ttl)) < 0) \
    FAIL_WITH_WARN(sock, "sock=%d, ttl=%d", sock, ttl);                 \
  return true;                                                          \
} while (0)
//
#ifdef ENABLE_QOS
#define NET_SETTOS(PROTO_VERSION, TOS_TYPE) do {        \
  int okay = true;                                      \
  int qos = run_opts.qos & 0xff;                        \
  if (qos)                                              \
    okay = (setsockopt(sock, PROTO_VERSION, TOS_TYPE,   \
      &qos, sizeof(qos)) >= 0);                         \
  if (!okay)                                            \
    WARNXT("%s: sock=%d, tos=%d", __func__, sock, qos); \
  return okay;                                          \
} while (0)
#endif
//
#ifdef ENABLE_QOS4
bool set_tos4(int sock) { NET_SETTOS(IPPROTO_IP, IP_TOS); }
#endif
bool set_ttl4(int sock, int ttl) { NET_SETTTL(IPPROTO_IP, IP_TTL); }
//
#ifdef ENABLE_IPV6
#ifdef ENABLE_QOS6
bool set_tos6(int sock) { NET_SETTOS(IPPROTO_IPV6, IPV6_TCLASS); }
#endif
bool set_ttl6(int sock, int ttl) { NET_SETTTL(IPPROTO_IPV6, IPV6_UNICAST_HOPS); }
#endif
//
#undef NET_SETTOS
#undef NET_SETTTL

#ifdef USE_RAW
// Create TCP socket for hop 'at', and try to connect (poll results later)
bool ping_tcp(int at) {
#define SET_ADDR_PORT(src_addr, ssa_addr, dst_addr, dst_port) { \
  addr_copy(&(src_addr), &(ssa_addr));   \
  addr_copy(&(dst_addr), remote_ipaddr); \
  (dst_port) = htons((run_opts.port > 0) ? run_opts.port : TCP_DEFAULT_PORT); \
}
  int sock = socket(af, SOCK_STREAM, 0);
  if (sock < 0)
    FAIL_WITH_WARN(sock, "socket[at=%d]", at);
  int ttl = at + 1;
  if (!(netkit.set_ttl && netkit.set_ttl(sock, ttl))) {
    close(sock);
    return false;
  }
  /*summ*/ sum_sock[0]++;
  //
  struct sockaddr_storage local  = {.ss_family = af};
  struct sockaddr_storage remote = {.ss_family = af};
  switch (af) {
    case AF_INET:
      SET_ADDR_PORT(SADDR4(&local), SADDR4(&lsa), SADDR4(&remote), SPORT4(&remote));
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      SET_ADDR_PORT(SADDR6(&local), SADDR6(&lsa), SADDR6(&remote), SPORT6(&remote));
      break;
#endif
    default:
      FAIL_POSTPONE(EAFNOSUPPORT, af);
  }
  uint salen = netkit.salen;
  if (bind(sock, SA(&local), salen))
    FAIL_WITH_WARN(sock, "bind[at=%d]", at);
  if (getsockname(sock, SA(&local), &salen))
    FAIL_WITH_WARN(sock, "getsockname[at=%d]", at);
  int flags = fcntl(sock, F_GETFL, 0);
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0)
    FAIL_WITH_WARN(sock, "fcntl(O_NONBLOCK)[at=%d]", at);
  //
  int port = 0;
  switch (af) {
    case AF_INET:
      port = ntohs(SPORT4(&local));
    break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      port = ntohs(SPORT6(&local));
    break;
#endif
    default:
      FAIL_POSTPONE(EAFNOSUPPORT, af);
  }
  //
  int seq = port % MAXSEQ;
  if (poll_reg_fd(sock, seq) < 0)
    FAIL_AND_CLOSE(EOVERFLOW, sock, "at=%d: %s", at, NOPOOL_ERR);
  save_sequence(seq, at);
  if (!save_curr_ts(seq))
    return false;
  connect(sock, SA(&remote), salen); // NOLINT(bugprone-unused-return-value)
#ifdef LOGMOD
  { struct timespec now;
    int rc = clock_gettime(CLOCK_MONOTONIC, &now); // LOGMOD for debug only
    LOGMSG("at=%d seq=%d sock=%d: ttl=%d (ts=%lld.%09ld)",
      at, seq, sock, ttl, rc ? 0 : (long long)now.tv_sec, rc ? 0 : now.tv_nsec);
  }
#endif
  /*summ*/ net_queries[QR_SUM]++; net_queries[QR_TCP]++;
  return true;
#undef SET_ADDR_PORT
}
#endif

void fill_icmph(uint8_t type, uint16_t id, uint16_t seq, _icmphdr *icmp) { // NONNULL(4)
  icmp->type = type;
  icmp->code = 0;
  icmp->sum  = 0;
  icmp->id   = htons(id);
  icmp->seq  = htons(seq);
  LOGMSG("icmp: seq=%d id=%u", ntohs(icmp->seq), ntohs(icmp->id));
}

void fill_udph(uint16_t seq, _udphdr *udp, uint16_t size) { // NONNULL(2)
  udp->uh_sum  = 0;
  udp->uh_ulen = htons(size);
  if (run_opts.port < 0)
    SET_UDP_UH_PORTS(udp, portpid, LO_UDPPORT + seq)
  else
    SET_UDP_UH_PORTS(udp, LO_UDPPORT + seq, run_opts.port);
  LOGMSG("udp: seq=%d port=%u", seq, ntohs(udp->uh_dport));
}

#ifdef ENABLE_IPV6
bool set_opt_ck6(int sock) {
  // checksumming by kernel
  int opt = 6;
  if (setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &opt, sizeof(opt)) < 0) {
    LOGMSG("sock=%d", sock);
    FAIL_WITH_WARN(sock, "%s", "setsockopt6(IPV6_CHECKSUM)");
  }
  return true;
}
#endif

