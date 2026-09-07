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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <assert.h>

#if defined(LOG_NET) && !defined(LOGMOD)
#define LOGMOD
#endif

#if !defined(LOG_NET) && defined(LOGMOD)
#undef LOGMOD
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "net.h"
#include "gen.h"
#ifdef USE_RAW
#include "raw.h"
#else
#include "user.h"
#endif
#include "aux.h"
#include "nls.h"
#include "polling.h"

#ifdef ENABLE_DNS
#include "dns.h"
#endif

#ifdef HAVE_ARC4RANDOM_UNIFORM
#  define RANDUNIFORM(base) arc4random_uniform(base)
#else // original version
#  define RANDUNIFORM(base) ((base - 1) * (rand() / (RAND_MAX + 0.1)))
#endif

#if   __STDC_VERSION__ > 202312L
#  define SASSERT  static_assert
#elif __STDC_VERSION__ > 201112L
#  define SASSERT _Static_assert
#else
#  define SASSERT(expression, ...) assert(expression)
#endif

#if !defined(ICMP_TIME_EXCEEDED) && defined(ICMP_TIMXCEED)
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#endif

typedef struct PACKIT _iphdr {
  uint8_t bytes[20];
} _iphdr;

#ifdef WITH_MPLS
struct PACKIT icmpext_struct { // RFC4884
  #if BYTE_ORDER == LITTLE_ENDIAN
  uint8_t res:4;
  uint8_t ver:4;
  #elif BYTE_ORDER == BIG_ENDIAN
  uint8_t ver:4;
  uint8_t res:4;
  #else
    #error "Undefined byte order"
  #endif
  uint8_t rest;
  uint16_t sum;
}; /* must be 4 bytes */
//
struct PACKIT icmpext_object { // RFC4884
  uint16_t len;
  uint8_t class;
  uint8_t type;
}; /* must be 4 bytes */
//
#define ICMP_EXT_VER        2
#define ICMP_EXT_CLASS_MPLS 1
#define ICMP_EXT_TYPE_MPLS  1
#define IES_SZ sizeof(struct icmpext_struct)
#define IEO_SZ sizeof(struct icmpext_object)
#define LAB_SZ sizeof(mpls_label_t)
#define MPLSMIN 120 // min after: [ip] icmp ip
#endif /*MPLS*/

// global
int proto = IPPROTO_ICMP; // ICMP as default packet type
char localaddr[MAX_ADDRSTRLEN];
bool reset_pattern = true;
bool reset_pldsize = true;
ping_fn netping;

//

static size_t ipicmphsz; // set in net_settings()
static size_t minfailsz; // set in net_settings:net_protoset()
static size_t hdr_minsz;
static size_t sa_addr_offset;
static socklen_t sa_len;

static int batch_at;
static int numhosts = BATCH_HOSTS;
static int stopper  = MAXHOST;


//

// return in 'tv' waittime before sending the next ping
void waitspec(struct timespec *tv) {
  double wait = run_opts.interval;
  int num = numhosts;
  int first = run_opts.minttl - 1;
  if ((first > 0) && (num > first))
    num -= first;
  wait /= num;
  tv->tv_sec = trunc(wait);
  tv->tv_nsec = (wait - tv->tv_sec) * NANO;
}

static void hop_stats(int at, timemsec_t curr) {
  double curr_f = msec2float(curr);
  LOGMSG("prev=%lld.%09ld curr=%lld.%09ld",
    (long long)hop[at].last.ms, hop[at].last.frac,
    (long long)curr.ms, curr.frac);
  //
  if (hop[at].recv < 1) {
    hop[at].best = hop[at].worst = curr;
    hop[at].mean = curr_f;
    hop[at].var  = hop[at].jitter = hop[at].jworst = hop[at].jinta = hop[at].avg = 0;
  } else {
    double jitter  = float_sub_msec(curr, hop[at].last);
    hop[at].jitter = (jitter < 0) ? -jitter : jitter; // abs()
  }
  hop[at].last = curr;
  //
  if (mseccmp(curr, hop[at].best, <))
     hop[at].best   = curr;
  if (mseccmp(curr, hop[at].worst, >))
     hop[at].worst  = curr;
  if (hop[at].jitter > hop[at].jworst)
     hop[at].jworst = hop[at].jitter;
  //
  hop[at].recv++;
  double davg    = curr_f - hop[at].avg;
  hop[at].avg   += davg / hop[at].recv;
  hop[at].var   += davg * (curr_f - hop[at].avg);
  hop[at].javg  += (hop[at].jitter - hop[at].javg)  / hop[at].recv;
  hop[at].jinta += (hop[at].jitter - hop[at].jinta) / 16; /* RFC1889 A.8 */
  //
  if (hop[at].recv > 1) {
    double inv_recv = 1 / (double)hop[at].recv;
    hop[at].mean = pow(hop[at].mean, 1 - inv_recv) * pow(curr_f, inv_recv);
  }
  //
  hop[at].up = true;
  hop[at].transit = false;
  if (run_opts.cache > 0)
    hop[at].seen = time(NULL);
}

// return index of 'addr' at hop 'at', otherwise -1
static int addr2ndx(int at, const t_ipaddr *addr) NONNULL(2);
static int addr2ndx(int at, const t_ipaddr *addr) {
  for (int i = 0; i < MAXPATH; i++)
    if (addr_equal(&IP_AT_NDX(at, i), addr))
      return i;
  return -1;
}

// return first free slot at hop 'at', otherwise -1
static int at2next(int at) {
  for (int i = 0; i < MAXPATH; i++)
    if (!addr_exist(&IP_AT_NDX(at, i)))
      return i;
  return -1;
}

// set new ip-addr and clear associated data
static void set_new_addr(int at, int ndx, const t_ipaddr *ipaddr) NONNULL(3);
static void set_new_addr(int at, int ndx, const t_ipaddr *ipaddr) {
  addr_copy(&IP_AT_NDX(at, ndx), ipaddr);
  if (QPTR_AT_NDX(at, ndx)) {
    free(QPTR_AT_NDX(at, ndx));
    QPTR_AT_NDX(at, ndx) = NULL;
  }
  if (RPTR_AT_NDX(at, ndx)) {
    free(RPTR_AT_NDX(at, ndx));
    RPTR_AT_NDX(at, ndx) = NULL;
  }
#ifdef WITH_IPINFO
  if (QTXT_AT_NDX(at, ndx)) {
    free(QTXT_AT_NDX(at, ndx));
    QTXT_AT_NDX(at, ndx) = NULL;
  }
  for (uint i = 0; i < II_REC_ARR_LEN; i++) {
    if (II_VIEW_AT(at, ndx, i)) {
      free(II_VIEW_AT(at, ndx, i));
      II_VIEW_AT(at, ndx, i) = NULL;
    }
    for (uint j = 0; j < II_SRC_ARR_LEN; j++) {
      if (II_SRC_AT(at, ndx, i, j)) {
        free(II_SRC_AT(at, ndx, i, j));
        II_SRC_AT(at, ndx, i, j) = NULL;
      }
    }
  }
#endif
}

// set mpls for new ip-addr
#ifdef WITH_MPLS
static inline void set_new_mpls(int at, int ndx, const mpls_data_t *mpls) {
  void *atndx = &MPLS_AT_NDX(at, ndx);
  size_t size = sizeof(mpls_data_t);
  if (mpls)
    memcpy(atndx, mpls, size);
  else
    memset(atndx, 0,    size);
}
#define SET_NEW_ADDR(addr, mpls) do { \
  set_new_addr(at, ndx, (addr));      \
  set_new_mpls(at, ndx, (mpls));      \
} while (0)
#else
#define SET_NEW_ADDR(addr, unused) set_new_addr(at, ndx, (addr))
#endif

// Got a return
static int net_stat(uint port, const void *addr, struct timespec *recv_at, int reason
#ifdef WITH_MPLS
  , const mpls_data_t *mpls
#endif
) NONNULL(2, 3);
static int net_stat(uint port, const void *addr, struct timespec *recv_at, int reason
#ifdef WITH_MPLS
  , const mpls_data_t *mpls
#endif
) {
  uint seq = port % MAXSEQ;
  if (!seqlist[seq].transit)
    return true;
  //
  seqlist[seq].transit = false;
  int at = seqlist[seq].at;
  //
#ifdef WITH_MPLS
  LOGMSG("at=%d seq=%d (labels=%d)", at, seq, mpls ? mpls->n : 0);
#else
  LOGMSG("at=%d seq=%d", at, seq);
#endif
  //
  if (reason == RE_UNREACH) {
    if (at < stopper)
      stopper = at;    // set stopper
  } else if (stopper == at)
    stopper = MAXHOST; // clear stopper
  //
  if (at > stopper)    // return unless reachable
    return true;
  //
  int ndx = addr2ndx(at, addr);
  if (ndx < 0) {       // new one
    ndx = at2next(at);
    if (ndx < 0) {
      // no free slots? - warn once, and change the last one
      static bool warn_exceed_once;
      if (!warn_exceed_once) {
        warnx("%s=%d (MAXPATH=%d): %s", HOP_STR, at, MAXPATH, strerror(EOVERFLOW));
        warn_exceed_once = true;
      }
      ndx = MAXPATH - 1;
    }
    SET_NEW_ADDR(addr, mpls);
  }
#ifdef WITH_MPLS
  else if (mpls && memcmp(&MPLS_AT_NDX(at, ndx), mpls, sizeof(mpls_data_t))) {
    LOGMSG("update mpls at=%d ndx=%d (labels=%d)", at, ndx, mpls->n);
    set_new_mpls(at, ndx, mpls);
  }
#endif
  //
  struct timespec tv;
  timespecsub(recv_at, &seqlist[seq].time, &tv);
  timemsec_t curr = {.ms = time2msec(tv), .frac = time2mfrac(tv)};
  hop_stats(at, curr);
  //
#ifdef TUIMODE
  int n = seqlist[seq].saved_seq - hop[at].saved_seq_offset;
  if ((n >= 0) && (n <= SAVED_PINGS))
    hop[at].saved[n] = time2usec(tv);
#endif
  return true;
}

#ifdef WITH_MPLS
#define NET_STAT(port, addr, recvat, reason, mpls)   net_stat((port), (addr), (recvat), (reason), (mpls))
#else
#define NET_STAT(port, addr, recvat, reason, unused) net_stat((port), (addr), (recvat), (reason))
#endif

#ifdef WITH_MPLS
static inline bool mplslike(ssize_t psize, ssize_t hsize) {
  return (run_opts.mpls && ((psize - hsize) >= MPLSMIN));
}

static mpls_data_t *decodempls(const uint8_t *data, int size) {
  // given: icmpext_struct(4) icmpext_object(4) label(4) [label(4) ...]
  static const size_t mplsoff = MPLSMIN - (IES_SZ + IEO_SZ + LAB_SZ);
  static const size_t ieomin = IEO_SZ + LAB_SZ;
  if (size < MPLSMIN) {
    LOGMSG("got %u bytes of data, whereas mpls min is %u", size, MPLSMIN);
    return NULL;
  }
  uint off = mplsoff; // at least 12bytes ahead: icmp_ext_struct(4) icmp_ext_object(4) label(4) [label(4) ...]
  // icmp extension structure
  struct icmpext_struct *ies = (struct icmpext_struct *)&data[off];
  if ((ies->ver != ICMP_EXT_VER) || ies->res || !ies->sum) {
    LOGMSG("got ver=%u res=%u sum=%u, expected ver=%u res=0 sum!=0", ies->ver, ies->res, ies->sum, ICMP_EXT_VER);
    return NULL;
  }
  off += IES_SZ;
  // icmp extension object
  struct icmpext_object *ieo = (struct icmpext_object *)&data[off];
  ieo->len = ntohs(ieo->len);
  if ((ieo->len < ieomin) || (ieo->class != ICMP_EXT_CLASS_MPLS) || (ieo->type != ICMP_EXT_TYPE_MPLS)) {
    LOGMSG("got len=%u class=%u type=%u, expected len>=%zd class=%u type=%u",
      ieo->len, ieo->class, ieo->type, ieomin, ICMP_EXT_CLASS_MPLS, ICMP_EXT_TYPE_MPLS);
    return NULL;
  }
  uint8_t n = (ieo->len - IEO_SZ) / LAB_SZ;
  off += IEO_SZ;
  // limit number of MPLS labels
  static mpls_data_t mplsdata;
  if (n > ARRAY_LEN(mplsdata.label)) {
    LOGMSG("got %u MPLS labels, limit=%zu", n, ARRAY_LEN(mplsdata.label));
    n = ARRAY_LEN(mplsdata.label);
  }
  // mpls labels
  memset(&mplsdata, 0, sizeof(mplsdata));
  while ((mplsdata.n < n) && ((off + LAB_SZ) <= (size_t)size)) {
    mplsdata.label[mplsdata.n++].u32 = ntohl(*(uint32_t*)&data[off]);
    off += LAB_SZ;
  }
  return &mplsdata;
}
#endif

static int got_icmp_udp(const _udphdr *uh); // NONNULL(1);
static int got_icmp_udp(const _udphdr *uh) {
  int seq = -1;
  if (run_opts.port < 0) {
    if (ntohs(uh->uh_sport) == portpid)
      seq = ntohs(uh->uh_dport);
  } else {
    if (ntohs(uh->uh_dport) == run_opts.port)
      seq = ntohs(uh->uh_sport);
  }
  if (seq >= 0) {
    seq -= LO_UDPPORT;
    /*summ*/ net_replies[QR_UDP]++;
  }
  return seq;
}

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

void net_icmp_parse(struct timespec *recv_at) { // NONNULL(1)
  uint8_t packet[MAXPACKET];
  struct sockaddr_storage sa_in;
  //
  ssize_t size = recvfrom(RECVSOCK, packet, MAXPACKET, 0, (struct sockaddr *)&sa_in, &sa_len);
  LOGMSG("got %zd bytes", size);
  if (size < (ssize_t)hdr_minsz)
    LOGRET("incorrect packet size %zd [af=%d proto=%d minsize=%zd]", size, af, proto, hdr_minsz);
  //
  _icmphdr *icmp = (_icmphdr*)(packet + IPHSZ_IN_REPLY);
  uint8_t *data = ((uint8_t*)icmp) + ipicmphsz;
  //
#ifdef WITH_MPLS
  bool mplson = false;
#endif
  int seq = -1, reason = -1;
  switch (proto) {
    case IPPROTO_ICMP: {
      if (icmp->type == echo_reply) {
        seq = get_valid_seq(icmp);
        if (seq < 0)
          return;
        reason = RE_PONG;
      } else
      if ((icmp->type == time_exceed) || (icmp->type == dst_unreach)) {
        if (size < (ssize_t)minfailsz)
          LOGRET("incorrect packet size %zd [af=%d proto=%d expect>=%zd]", size, af, proto, minfailsz);
        seq = get_valid_seq((_icmphdr *)data);
        if (seq < 0)
          return;
        MPLS_LIKE_TEST;
        reason = (icmp->type == time_exceed) ? RE_EXCEED : RE_UNREACH;
      }
      LOGMSG_ICMP;
      if (seq >= 0) /*summ*/ net_replies[QR_ICMP]++;
    } break;
    case IPPROTO_UDP: {
      seq = got_icmp_udp((_udphdr *)data);
      if (seq < 0)
        return;
      MPLS_LIKE_TEST;
      LOGMSG_UDP;
    } break;
    case IPPROTO_TCP: {
      _tcphdr *th = (_tcphdr *)data;
      seq = ntohs(th->th_sport);
      MPLS_LIKE_TEST;
      LOGMSG_TCP;
      if (seq >= 0) /*summ*/ net_replies[QR_TCP]++;
    } break;
    default: LOGRET("Unsupported proto %d", proto);
  }
  /*summ*/ net_replies[QR_SUM]++;
  if (seq >= 0)
    NET_STAT(seq, ((uint8_t*)&sa_in) + sa_addr_offset, recv_at, reason,
             mplson ? decodempls(data, size - (data - packet)) : NULL);
}

int net_color(int at) {
  int sent = hop[at].sent - (int)hop[at].transit;
  int recv = hop[at].recv;
  return ((recv < sent) ? (recv ? 1/*yellow*/ : 2/*red*/) : 0/*norm*/);
}

const char *net_elem(int at, char key) {
  static char elemstr[NETELEM_MAXLEN];
  int ival = -1;
  switch (key) {
    case 'D':  // Dropped Packets
      ival = hop[at].sent - hop[at].recv - (int)hop[at].transit; break;
    case 'R':  // Received Packets
      ival = hop[at].recv; break;
    case 'S':  // Sent Packets
      ival = hop[at].sent; break;
    default: break;
  }
  if (ival >= 0) {
    snprinte(elemstr, sizeof(elemstr), "%d", ival);
    return elemstr;
  }
  double val = NAN;
  char *suffix = NULL;
  switch (key) {
    case 'N':   // Newest RTT(msec)
      val = msec2float(hop[at].last); break;
    case 'B':   // Min/Best RTT(msec)
      val = msec2float(hop[at].best); break;
    case 'A':   // Average RTT(msec)
      val = hop[at].avg; break;
    case 'W':   // Max/Worst RTT(msec)
      val = msec2float(hop[at].worst); break;
    case 'G':   // Geometric Mean
      val = hop[at].mean; break;
    case 'L': { // Loss Ratio
      int known = hop[at].sent - (int)hop[at].transit; // transit ? 1 : 0;
      val = known ? (100 - (100.0 * hop[at].recv / known)) : 0;
      suffix = "%";
      } break;
    case 'V': { // Standard Deviation
      int re = hop[at].recv - 1;
      val = (re > 0) ? sqrt(hop[at].var / re) : 0;
      } break;
    case 'J':   // Current Jitter
      val = hop[at].jitter; break;
    case 'M':   // Jitter Mean/Avg
      val = hop[at].javg; break;
    case 'X':   // Worst Jitter
      val = hop[at].jworst; break;
    case 'I':   // Interarrival Jitter
      val = hop[at].jinta; break;
    default: return NULL;
  }
  snprinte(elemstr, sizeof(elemstr), "%.*f%s", val2len(val), val, suffix ? suffix : "");
  return elemstr;
}

int net_max(void) {
  int max = 0;
  int maxat = (run_opts.maxttl > MAXHOST) ? MAXHOST : run_opts.maxttl;
  for (int at = 0; at < maxat; at++) {
    if (addr_equal(&CURRENT_IP(at), remote_ipaddr)) {
      max = at + 1;
      if (run_opts.endpoint && (run_opts.minttl != max))
        run_opts.minttl = max;
      break;
    }
    if (addr_exist(&CURRENT_IP(at))) {
      max = at + 2;
      if (run_opts.endpoint && (run_opts.minttl != (at + 1)))
        run_opts.minttl = at + 1; // max-1: show previous known hop
    }
  }
  if (max > maxat)
    max = maxat;
  return max;
}

inline int net_min(void) {
  return (run_opts.minttl > 0) ? (run_opts.minttl - 1) : 0;
}

inline void net_end_transit(void) { for (int at = 0; at < MAXHOST; at++) hop[at].transit = false; }

static inline void set_bit_pattern(void) {
  if (run_opts.pattern < 0)
    bitpattern = (uint8_t)RANDUNIFORM(UINT8_MAX + 1);
  else {
    bitpattern = run_opts.pattern;
    reset_pattern = false;
  }
  LOGMSG("%u (0x%02X)", bitpattern, bitpattern);
}

static inline void set_payload_size(void) {
  if (run_opts.size < 0)
    payloadsize = RANDUNIFORM(-run_opts.size);
  else {
    payloadsize = run_opts.size;
    reset_pldsize = false;
  }
  if (payloadsize > (MAXPACKET - MINPACKET)) payloadsize = MAXPACKET - MINPACKET;
  LOGMSG("%u", payloadsize);
}

int net_send_batch(void) {
  if (reset_pattern)
    set_bit_pattern();
  if (reset_pldsize)
    set_payload_size();
  //
  // Send packet if needed
  { bool pingat = true;
    if ((run_opts.cache > 0) && hop[batch_at].up && (hop[batch_at].seen > 0)
      && ((time(NULL) - hop[batch_at].seen) <= run_opts.cache))
        pingat = false;
    if (pingat && netping && !netping(batch_at))
      LOGRET_RC(-1, "%s", "failed");
  }
  // Calculate rc for caller
  { int n_unknown = 0;
    for (int at = net_min(); at < batch_at; at++) {
      if (!addr_exist(&CURRENT_IP(at)))
        n_unknown++;
      if (addr_equal(&CURRENT_IP(at), remote_ipaddr))
        n_unknown = MAXHOST; // Make sure we drop into "we should restart"
    }
    if (addr_equal(&CURRENT_IP(batch_at), remote_ipaddr) // success in reaching target
        || (n_unknown > BATCH_HOSTS)           // fail in consecuitive MAX_UNKNOWN_HOSTS
        || (batch_at >= (run_opts.maxttl - 1)) // or reach limit
        || (batch_at >= stopper)) {            // or learnt unreachable
      numhosts = batch_at + 1;
      batch_at = net_min();
      LOGMSG("stop at hop #%d", numhosts);
      return 1;
    }
  }
  //
  batch_at++;
  return 0;
}

void net_reset(void) {
  // clear all query-response cache
  for (int at = 0; at < MAXHOST; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      SET_NEW_ADDR(&unspec_addr, NULL);
  //
  memset(hop, 0, sizeof(hop));
#ifdef TUIMODE
  for (int at = 0; at < MAXHOST; at++) {
    for (int i = 0; i < SAVED_PINGS; i++)
      hop[at].saved[i] = CT_UNSENT; // unsent
    hop[at].saved_seq_offset = -SAVED_PINGS + 2;
  }
#endif
  poll_close_tcpfds();
  for (int i = 0; i < MAXSEQ; i++)
    seqlist[i].transit = false;
  batch_at = net_min();
  stopper  = MAXHOST;
  numhosts = BATCH_HOSTS;
}

bool net_set_host(const t_ipaddr *addr) { // NONNULL(1)
  rsa.SA_AF = af;
  switch (af) {
    case AF_INET:
      set_sock4();
      addr_copy(&rsa.S_ADDR, addr);
      remote_ipaddr = (t_ipaddr*)&rsa.S_ADDR;
    break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      set_sock6();
      addr_copy(&rsa.S6ADDR, addr);
      remote_ipaddr = (t_ipaddr*)&rsa.S6ADDR;
    break;
#endif
    default:
      return false;
  }
  if ((RECVSOCK < 0) || ((proto != IPPROTO_TCP) && (SENDSOCK < 0))) {
    WARNXT("%s", NOSOCK_ERR);
    return false;
  }
  if (!addr_exist(remote_ipaddr)) {
    WARNXT("%s: %s", TARGET_STR, strerror(EINVAL));
    return false;
  }
  //
  net_reset();
  { struct sockaddr_storage ss = {0};
    socklen_t len = sizeof(ss);
    if (getsockname(RECVSOCK, (struct sockaddr *)&ss, &len) < 0)
      WARNX("%s", "getsockname()");
    else {
      if (len > sizeof(ss))
        WARNXT("%s: %d > %zd: %s", "recv-socket", len, sizeof(ss), strerror(EINVAL));
      int saf = ss.ss_family;
      char *src =
#ifdef ENABLE_IPV6
        (saf == AF_INET6) ? (char*)&((struct sockaddr_in6 *)&ss)->sin6_addr :
#endif
        ((saf == AF_INET) ? (char*)&((struct sockaddr_in  *)&ss)->sin_addr  : NULL);
      if (!src)
        WARNXT("%d: %s", saf, strerror(EAFNOSUPPORT));
      else if (!inet_ntop(saf, src, localaddr, sizeof(localaddr))) {
        WARNT("%s", "inet_ntop()");
        localaddr[0] = 0;
      }
    }
  }
  portpid = IPPORT_RESERVED + pid16 % (USHRT_MAX - IPPORT_RESERVED);
  return true;
}

bool net_set_ifaddr(const char *ifaddr) { // NONNULL(1)
  int len = 0;
  lsa.SA_AF = af;
  switch (af) {
    case AF_INET:
      lsa.S_PORT = 0;
      if (!inet_aton(ifaddr, &lsa.S_ADDR)) {
        warnx("%s: %s", ifaddr, strerror(EFAULT));
        return false;
      }
      len = sizeof(lsa.sin);
      break;
#ifdef ENABLE_IPV6
    case AF_INET6:
      lsa.S6PORT = 0;
      if (inet_pton(af, ifaddr, &lsa.S6ADDR) < 1) {
        warnx("%s: %s", ifaddr, strerror(EFAULT));
        return false;
      }
      len = sizeof(lsa.sin6);
      break;
#endif
    default: break;
  }
  if (bind(SENDSOCK, &lsa.sa, len) < 0) {
    warn("bind(%d)", SENDSOCK);
    return false;
  }
  return true;
}

void net_close(void) {
  close_sock46();
  // clear memory allocated for query-response cache
  for (int at = 0; at < MAXHOST; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      SET_NEW_ADDR(&unspec_addr, NULL);
}

static int err_slippage(int sock) {
  socklen_t namelen = sizeof(rsa);
  int rc = getpeername(sock, &rsa.sa, &namelen);
  if ((rc < 0) && (errno == ENOTCONN)) {
    rc = read(sock, &namelen, 1);
    if (rc >= 0) return -1; // sanity lost
    rc = errno;
  } else rc = 0;
  return rc;
}

// Check connection state with error-slippage
void net_tcp_parse(int sock, int seq, int noerr, struct timespec *recv_at) { // NONNULL(4)
  int reason = -1, e = err_slippage(sock);
  LOGMSG("recv <e=%d> sock=%d ts=%lld.%09ld", e, sock, (long long)recv_at->tv_sec, recv_at->tv_nsec);
  // if no errors, or connection refused, or host down, the target is probably reached
  switch (e) {
    case EHOSTUNREACH:
    case ENETUNREACH:
      reason = RE_UNREACH;
      // fall through
    case EHOSTDOWN:
    case ECONNREFUSED:
    case 0: // no error
      /*no MPLS decoding?*/
      if (remote_ipaddr)
        NET_STAT(seq, remote_ipaddr, recv_at, reason, NULL);
      LOGMSG("stat seq=%d for sock=%d", seq, sock);
      break;
//  case EAGAIN: // need to wait more
    default: break;
  }
  seqlist[seq].transit = false;
  if (noerr) { /*summ*/ net_replies[QR_SUM]++; net_replies[QR_TCP]++; }
}

// Clean timed out TCP connection
bool net_timedout(int seq) {
  struct timespec now, dt;
  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
    keep_error(errno, __func__);
    return false;
  }
  timespecsub(&now, &seqlist[seq].time, &dt);
  if (time2msec(dt) <= run_opts.syn)
    return false;
  LOGMSG("clean tcp seq=%d after %d sec", seq, run_opts.syn / MIL);
  seqlist[seq].transit = false;
  return true;
}

#ifdef ENABLE_DNS
static void save_ptr_answer(int at, int ndx, const char* answer, size_t alen) {
  if (RPTR_AT_NDX(at, ndx)) {
#ifdef LOGMOD
    char str[MAX_ADDRSTRLEN] = {0};
    LOGMSG("resolv update at=%d ndx=%d for %s", at, ndx,
      addr2str(&IP_AT_NDX(at, ndx), sizeof(str), str));
#endif
    free(RPTR_AT_NDX(at, ndx));
    RPTR_AT_NDX(at, ndx) = NULL;
  }
  size_t lim = (alen < NAMELEN) ? alen : NAMELEN;
  if (strnlen(answer, lim))
    RPTR_AT_NDX(at, ndx) = strndup(answer, lim);
  else { // if no answer, save ip-address in text representation
    char str[MAX_ADDRSTRLEN] = {0};
    RPTR_AT_NDX(at, ndx) = strndup(addr2str(&IP_AT_NDX(at, ndx), sizeof(str), str), NAMELEN);
  }
  if (!RPTR_AT_NDX(at, ndx))
    WARN("[%d:%d] strndup()", at, ndx);
}
#endif

void net_assert(void) { // to be sure
  SASSERT(sizeof(_icmphdr) == 8,  "icmp header");
  SASSERT(sizeof(_udphdr)  == 8,  "udp header");
  SASSERT(sizeof(_iphdr)   == 20, "ip4 header");
#ifdef WITH_MPLS
  SASSERT(IES_SZ == 4, "mpls ies");
  SASSERT(IEO_SZ == 4, "mpls ieo");
  SASSERT(LAB_SZ == 4, "mpls label");
#endif
  net_settings(IPV6_UNDEF);
}

int net_wait(void) { return RECVSOCK; }

void set_protosock(int type) {
  proto = type;
#ifdef ENABLE_IPV6
  if (af == AF_INET6)
    set_sock6();
  else
#endif
  { set_sock4(); }
}

void net_protoset(int type) {
  LOGMSG("proto type: %d", type);
  set_protosock(type);
  hdr_minsz = IPHSZ_IN_REPLY;
  netping = NULL;
  switch (type) {
    case IPPROTO_ICMP: hdr_minsz += sizeof(_icmphdr); netping = ping_icmp; break;
    case IPPROTO_UDP:  hdr_minsz += sizeof(_udphdr);  netping = ping_udp;  break;
    case IPPROTO_TCP:  hdr_minsz += sizeof(_tcphdr);  netping = ping_tcp;  break;
    default: warnx("%d: %s", type, strerror(EPROTONOSUPPORT));
  }
  minfailsz = hdr_minsz + IPHSZ_IN_REPLY + sizeof(_icmphdr);
}

#define NET46SETS(n_sz, n_er, n_te, n_un) do { \
  sa_len      = n_sz; \
  echo_reply  = n_er; \
  time_exceed = n_te; \
  dst_unreach = n_un; \
} while (0)

void net_settings(enum IPV6_ENDIS ipv6) {
#ifdef ENABLE_DNS
  dns_ptr_handler = save_ptr_answer; // no checks, handler for net-module only
#endif
  if (ipv6 == IPV6_ENABLED) {
#ifdef ENABLE_IPV6
    af = AF_INET6;
    addr_exist = addr6exist;
    addr_equal = addr6equal;
    addr_copy  = addr6copy;
    ipicmphsz = sizeof(struct ip6_hdr) + sizeof(_icmphdr);
    sa_addr_offset = offsetof(struct sockaddr_in6, sin6_addr);
    NET46SETS(sizeof(struct sockaddr_in6), ICMP6_ECHO_REPLY, ICMP6_TIME_EXCEEDED, ICMP6_DST_UNREACH);
    set_sock6();
#endif
  } else { // IPv4 by default
    af = AF_INET;
    addr_exist = addr4exist;
    addr_equal = addr4equal;
    addr_copy  = addr4copy;
    ipicmphsz = sizeof(_iphdr) + sizeof(_icmphdr);
    sa_addr_offset = offsetof(struct sockaddr_in, sin_addr);
    NET46SETS(sizeof(struct sockaddr_in), ICMP_ECHOREPLY, ICMP_TIME_EXCEEDED, ICMP_UNREACH);
    set_sock4();
  }
  net_protoset(proto);
}

const char* addr2str(const t_ipaddr *addr, size_t size, char buff[size]) { // NONNULL(1, 3)
  const char *str = inet_ntop(af, addr, buff, size);
  return str ? str : UNKN_ITEM;
}

#ifdef WITH_MPLS
const char *mpls2str(const mpls_label_t *label, size_t size, char buff[size], uint indent) { // NONNULL(1, 3)
  snprinte(buff, size, "%*s[Lbl:%u Exp:%u S:%u TTL:%u]", indent, "",
    label->u.lab, label->u.exp, label->u.bos, label->u.ttl);
  return buff;
}
#endif

// type must correspond 'id' in 'ns_msg' (uint16_t)
// it's used as a hint for fast search, 16bits as [hash:7 at:6 ndx:3]
uint16_t str2hint(const char* str, uint16_t at, uint16_t ndx) {
  uint16_t hint = 0;
  uint8_t ch = 0;
  while ((ch = *str++))
    hint = ((hint << 5) + hint) ^ ch; // h * 33 ^ ch
  hint &= IDMASK;
  hint |= AT2ID(at);
  hint |= ID2NDX(ndx);
  return hint;
}

