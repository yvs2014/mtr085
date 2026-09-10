#ifndef NETDEF_H
#define NETDEF_H

#include "attr.h"
#include "common.h"

#define MAXHOST           64 // if you choose 256, then adjust masks: IDMASK ID2AT AT2ID ID2NDX
#define MAXPATH            8 // if you change it,  then adjust masks: IDMASK ID2AT AT2ID ID2NDX
#define MAXSEQ         16384 // maximum pings in processing
#define MAXPACKET       1500 // limit it to default MTU
#define MINPACKET         28 // 20 bytes IP and 8 bytes ICMP or UDP
#define PAYLOAD_SIZE      56 // default ICMP,UDP payload size (64 byte IP payload - 8 byte header)

#ifdef WITH_MPLS
#define MAX_MPLS_LABEL     8 // maximum mpls labels
#endif

#ifdef WITH_IPINFO
#define MAX_II_ITEMS      25
#define MAX_WHOIS_SOURCES 10
#endif

#ifdef TUIMODE
#define SAVED_PINGS      200
enum { CT_UNKN = -1, CT_UNSENT = -2, CT_SEAL = -3 };
#endif

#define PAUSE_BETWEEN_QUERIES 3 // pause between identical queries (and ipinfo too), in seconds
#define TXT_PTR_PAUSE         1 // pause between txt and ptr queries, in seconds

typedef struct atndx { int at, ndx, type; } atndx_t;

#ifdef WITH_MPLS
typedef union PACKIT mpls_label { // RFC4950
  struct {
#if BYTE_ORDER == LITTLE_ENDIAN
  uint32_t ttl:8;
  uint32_t bos:1;
  uint32_t exp:3;
  uint32_t lab:20;
#elif BYTE_ORDER == BIG_ENDIAN
  uint32_t lab:20;
  uint32_t exp:3;
  uint32_t bos:1;
  uint32_t ttl:8;
#else
#error "Undefined byte order"
#endif
  } u;
  uint32_t u32;
} mpls_label_t; /* must be 4 bytes */

typedef struct mpls_data {
  mpls_label_t label[MAX_MPLS_LABEL]; // N x 32b labels
  uint8_t n;
} mpls_data_t;
#endif

#ifdef WITH_IPINFO
typedef struct ii_record_view {
  char *view;
  char *src[MAX_WHOIS_SOURCES]; // records from all sources
} ii_record_view_t;
#endif

// Address(es) plus associated data
typedef struct eaddr {
  t_ipaddr ipaddr;
  char *q_ptr, *r_ptr;                // query, reply
#ifdef WITH_IPINFO
  char *q_txt;                        // query
  ii_record_view_t rec[MAX_II_ITEMS]; // parsed reply
#endif
  time_t q_ptr_ts; // timestamp when 'q_ptr' is sent
#ifdef WITH_IPINFO
  time_t q_txt_ts; // timestamp when 'q_txt' is sent
#endif
#ifdef WITH_MPLS
  mpls_data_t mpls;
#endif
} eaddr_t;

// time stats, in msec
typedef struct timemsec {
  time_t ms;  // in milliseconds
  long frac;  // in nanoseconds
} timemsec_t;

// Hop description
typedef struct hop {
  // addresses with all associated data (dns names, mpls labels, extended ip info)
  eaddr_t eaddr[MAXPATH];
  int current;            // index of the last received address
  // a lot of statistics
  int sent, recv;         // %d
  timemsec_t last, best, worst;  // >10 ? %d : %1.f [msec]
  double avg, mean;              // >10 ? %d : %1.f [msec]
  double jitter, javg, jworst, jinta; // jitters
  double var;                    // variance as base for std deviance: sqrt(var/(recv-1))
  bool transit, up;       // states: ping in transit, host alive
#ifdef TUIMODE
  int saved[SAVED_PINGS]; // map for display mode: <0 " ?" chars, >=0 pong in usec
  int saved_seq_offset;
#endif
  time_t seen;            // timestamp for caching, last seen
} hop_t;
extern hop_t hop[MAXHOST];

// hop indexing macros
#define CURRENT_IP(at)              (hop[at].eaddr[hop[at].current].ipaddr)
#define IP_AT_NDX(at, ndx)          (hop[at].eaddr[ndx].ipaddr)
#ifdef WITH_MPLS
#define CURRENT_MPLS(at)            (hop[at].eaddr[hop[at].current].mpls)
#define MPLS_AT_NDX(at, ndx)        (hop[at].eaddr[ndx].mpls)
#endif
#define QPTR_TS_AT_NDX(at, ndx)     (hop[at].eaddr[ndx].q_ptr_ts)
#define QPTR_AT_NDX(at, ndx)        (hop[at].eaddr[ndx].q_ptr)
#define RPTR_AT_NDX(at, ndx)        (hop[at].eaddr[ndx].r_ptr)
#ifdef WITH_IPINFO
#define QTXT_TS_AT_NDX(at, ndx)     (hop[at].eaddr[ndx].q_txt_ts)
#define QTXT_AT_NDX(at, ndx)        (hop[at].eaddr[ndx].q_txt)
#define II_VIEW_AT(at, ndx, num)    (hop[at].eaddr[ndx].rec[num].view)
#define II_SRC_AT(at, ndx, num, sn) (hop[at].eaddr[ndx].rec[num].src[sn])
#define II_REC_ARR(at, ndx)         (hop[at].eaddr[ndx].rec)
#define II_REC_ARR_LEN              ARRAY_LEN(II_REC_ARR(0, 0))
#define II_SRC_ARR(at, ndx, num)    (hop[at].eaddr[ndx].rec[num].src)
#define II_SRC_ARR_LEN              ARRAY_LEN(II_SRC_ARR(0, 0, 0))
#endif

extern int af;    // address family
extern int proto; // icmp-udp-tcp proto

extern char strerr_txt[NAMELEN];     // any target
extern char tgterr_txt[NAMELEN];     // current target
extern char logerr_txt[NAMELEN * 2]; // $func: $tgterr

//

bool  addr4exist(const void *a) NONNULL(1);
bool  addr4equal(const void *a, const void *b) NONNULL(1, 2);
void* addr4copy(void *dst, const void *src) NONNULL(1, 2);
#ifdef ENABLE_IPV6
bool  addr6exist(const void *a) NONNULL(1);
bool  addr6equal(const void *a, const void *b) NONNULL(1, 2);
void* addr6copy(void *dst, const void *src) NONNULL(1, 2);
#endif
extern bool  (*addr_exist)(const void *a) NONNULL(1); // true if not 0
extern bool  (*addr_equal)(const void *a, const void *b) NONNULL(1, 2);
extern void* (*addr_copy)(void *dst, const void *src) NONNULL(1, 2);

bool open_sock46(void);
void set_sock4(void);
bool sock4_ready(int type);
#ifdef ENABLE_IPV6
void set_sock6(void);
bool sock6_ready(int type);
#endif

void keep_error(int rc, const char *prefix) NONNULL(2);
const char* rstrerror(int rc);

#endif
