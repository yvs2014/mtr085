// net-common part of mtr085

#ifndef NETCOMMON_H
#define NETCOMMON_H

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#ifdef ENABLE_IPV6
#include <netinet/icmp6.h>
#endif

#include "netdef.h"

#define BATCH_HOSTS 10      // queries in batch

// struct icmphdr /* no common */
typedef struct PACKIT _icmphdr {
  uint8_t  type, code;
  uint16_t sum, id, seq;
} _icmphdr;
// struct tcphdr /* common because RFC793 */
// struct udphdr /* common because RFC768 */
typedef struct tcphdr _tcphdr;
typedef struct udphdr _udphdr;

typedef struct sequence {
  int at;
  bool transit;
  struct timespec time;
#ifdef TUIMODE
  int saved_seq;
#endif
} sequence_t;

typedef bool (*ping_fn)(int at);
extern ping_fn ping_icmp;
extern ping_fn ping_udp;

//

extern const t_ipaddr unspec_addr;
extern struct sockaddr_storage lsa, rsa; // local and remote sockaddr
extern t_ipaddr *remote_ipaddr;
extern uint8_t bitpattern;
extern uint16_t payloadsize;
extern int portpid;

extern sequence_t seqlist[MAXSEQ];

//

#ifdef USE_RAW
bool ping_tcp(int at);
#endif

void setsock_qos4(void);
#ifdef ENABLE_IPV6
void setsock_qos6(void);
#endif

#ifdef ENABLE_QOS4
bool set_tos4(int sock);
#endif
bool set_ttl4(int sock, int ttl);
//
#ifdef ENABLE_IPV6
#ifdef ENABLE_QOS6
bool set_tos6(int sock);
#endif
bool set_ttl6(int sock, int ttl);
#endif

bool save_curr_ts(int seq);

int new_sequence(int at);
void save_sequence(int seq, int at);
void fill_icmph(uint8_t type, uint16_t id, uint16_t seq, _icmphdr *icmp) NONNULL(4);
void fill_udph(uint16_t seq, _udphdr *udp, uint16_t size) NONNULL(2);
#ifdef ENABLE_IPV6
bool set_opt_ck6(int sock);
#endif

#define SET_UDP_UH_PORTS(uh, s, d) { (uh)->uh_sport = htons(s); (uh)->uh_dport = htons(d); }

//
#define FD_CLOSE(fd) if ((fd) >= 0) { close(fd); (fd) = -1; /*summ*/ sum_sock[1]++; }
//
#define NET_FAIL_WARN(fmt, ...) do {                     \
  WARNXF(fmt ": %s", __VA_ARGS__, tgterr_txt);           \
  snprinte(logerr_txt, sizeof(logerr_txt),               \
    fmt ": %s", __VA_ARGS__, tgterr_txt);                \
  LOGRET_RC(false, fmt ": %s", __VA_ARGS__, tgterr_txt); \
} while (0)
//
#define FAIL_AND_CLOSE(rcode, fd, fmt, ...) do { \
  rstrerror(rcode);                              \
  if (dispclear_fn) dispclear_fn();              \
  FD_CLOSE(fd);                                  \
  NET_FAIL_WARN(fmt, __VA_ARGS__);               \
} while (0)
//
#define FAIL_WITH_WARN(fd, fmt, ...) FAIL_AND_CLOSE(errno, fd, fmt, __VA_ARGS__)
//
#define FAIL_POSTPONE(rcode, rvalue) do  { \
  rstrerror(rcode);                        \
  NET_FAIL_WARN("%d", rvalue);             \
} while (0)

#endif
