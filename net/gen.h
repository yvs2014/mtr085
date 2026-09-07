// net-common part of mtr085

#ifndef GEN_H
#define GEN_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include "common.h"
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

//

extern int portpid;
#define LO_UDPPORT 33433 // start from LO_UDPPORT+1
#define UDPPORTS      90 // go thru udp:33434-33523 acl

extern const t_ipaddr unspec_addr;
extern t_sockaddr lsa, rsa; // local and remote sockaddr
extern t_ipaddr *remote_ipaddr;
extern uint8_t bitpattern;
extern uint16_t payloadsize;

extern sequence_t seqlist[MAXSEQ];
enum { RE_PONG, RE_EXCEED, RE_UNREACH }; // reason of a pong response

extern int echo_reply, time_exceed, dst_unreach;

//

bool ping_tcp(int at);

bool settosttl4(int sock, int ttl);
#ifdef ENABLE_IPV6
bool settosttl6(int sock, int ttl);
#endif

bool save_curr_ts(int seq);

int new_sequence(int at);
void save_sequence(int seq, int at);
void fill_icmph(uint8_t type, uint16_t id, uint16_t seq, _icmphdr *icmp) NONNULL(4);

//
#define FD_CLOSE(fd) if ((fd) >= 0) { close(fd); (fd) = -1; /*summ*/ sum_sock[1]++; }
//
#define NET_FAIL_WARN(fmt, ...) do {                     \
  WARNX(fmt ": %s", __VA_ARGS__, tgterr_txt);            \
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
