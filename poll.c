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
#include <poll.h>

#if defined(LOG_POLL) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_POLL) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "common.h"
#include "aux.h"

#include "mtr-poll.h"
#include "net.h"
#include "display.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#if defined(CURSESMODE) || defined(SPLITMODE)
#define SCROLL_LINES 5
#endif

enum { FD_BATCHMAX = 30 };
// between poll() calls
enum { MINSLEEP_USEC = 10 }; // in microseconds
enum { PAUSE_MSEC = 100 };   // in milliseconds

// base file descriptors
enum { FD_STDIN, FD_NET,
#ifdef ENABLE_DNS
       FD_DNS,
#ifdef ENABLE_IPV6
       FD_DNS6,
#endif
#endif
FD_MAX };

static long numpings;

enum { NO_GRACE, GRACE_START, GRACE_FINISH }; // state of grace period
static int grace;
static struct timespec grace_started;

static struct pollfd *allfds; // FDs
static int *tcpseq;           // and corresponding sequence indexes from net.c
static int maxfd;
static const struct timespec GRACETIME = { 5, 0 };
#ifdef ENABLE_DNS
static bool need_dns;
#endif

#define SET_POLLFD(ndx, sock) { allfds[ndx].fd = sock; allfds[ndx].revents = 0; }
#define IN_ISSET(ndx) ((allfds[ndx].fd >= 0) && ((allfds[ndx].revents & POLLIN) == POLLIN))
#define CLOSE_FD(ndx) { if (tcpseq) tcpseq[ndx] = -1; \
  if (allfds) { close(allfds[ndx].fd); allfds[ndx].fd = -1; allfds[ndx].revents = 0; /*summ*/ sum_sock[1]++;} \
}

static void set_fds(void) {
  SET_POLLFD(FD_STDIN, run_opts.interactive ? 0 : -1);
  SET_POLLFD(FD_NET, net_wait());
#ifdef ENABLE_DNS
  need_dns = run_opts.dns
#ifdef WITH_IPINFO
          || run_opts.lookup
#endif
  ;
  SET_POLLFD(FD_DNS, need_dns ? dns_wait(AF_INET) : -1);
#ifdef ENABLE_IPV6
  SET_POLLFD(FD_DNS6, need_dns ? dns_wait(AF_INET6) : -1);
#endif
#endif
  // clean rest triggers
  if ((mtrtype == IPPROTO_TCP) && (maxfd > FD_MAX))
    for (int i = FD_MAX; i < maxfd; i++)
      if (allfds[i].revents)
        allfds[i].revents = 0;
}

static int sock_already_accounted(int sock) {
  for (int i = FD_MAX; i < maxfd; i++) {
    if (allfds[i].fd == sock) {
      LOGMSG("sock=%d found in slot #%d", sock, i);
      return i;
    }
  }
  return -1;
}

static int save_in_vacant_slot(int sock, int seq) {
  for (int i = FD_MAX; i < maxfd; i++)
    if (allfds[i].fd < 0) {
      tcpseq[i] = seq;
      allfds[i].fd = sock;
      allfds[i].events = POLLOUT;
      LOGMSG("sock=%d seq=%d put in slot #%d", sock, seq, i);
      return i;
    }
  return -1;
}

static bool allocate_more_memory(void) {
  size_t tcpseq_size = (maxfd + FD_BATCHMAX) * sizeof(int);
  void *mem = realloc(tcpseq, tcpseq_size);
  if (!mem) {
    WARN("seq realloc(%zd)", tcpseq_size);
    return false;
  }
  tcpseq = (int*)mem;
  memset(&tcpseq[maxfd], -1, FD_BATCHMAX * sizeof(int));
  //
  size_t pollfd_size = (maxfd + FD_BATCHMAX) * sizeof(struct pollfd);
  mem = realloc(allfds, pollfd_size);
  if (!mem) {
    WARN("fd realloc(%zd)", pollfd_size);
    return false;
  }
  allfds = (struct pollfd *)mem;
  memset(&allfds[maxfd], -1, FD_BATCHMAX * sizeof(struct pollfd));
  maxfd += FD_BATCHMAX;
  LOGMSG("%zd bytes for %d slots added to pool", tcpseq_size + pollfd_size, FD_BATCHMAX);
  return true;
}

int poll_reg_fd(int sock, int seq) {
  int slot = sock_already_accounted(sock);
  if (slot < 0) {
    slot = save_in_vacant_slot(sock, seq);
    if (slot < 0) {
      if (allocate_more_memory()) {
        slot = save_in_vacant_slot(sock, seq);
        if (slot < 0)
          LOGMSG("sock=%d: assertion failed", sock);
      } else
        LOGMSG("sock=%d: memory allocation failed", sock);
    }
  }
  return slot;
}

void poll_dereg_fd(int slot) { if ((slot >=0) && (slot < maxfd)) CLOSE_FD(slot); }

void poll_close_tcpfds(void) {
  if ((maxfd > FD_MAX) && allfds)
    for (int i = FD_MAX; i < maxfd; i++)
      if (allfds[i].fd >= 0) CLOSE_FD(i);
}

// not relying on ETIMEDOUT close stalled TCP connections
static void tcp_timedout(void) {
  for (int i = FD_MAX; i < maxfd; i++) {
    int seq = tcpseq[i];
    if (seq >= 0) {
      bool timedout =
#ifdef WITH_IPINFO
        (seq < MAXSEQ) ? net_timedout(seq) : ipinfo_timedout(seq);
#else
        net_timedout(seq);
#endif
      if (timedout) {
        tcpseq[i] = -1;
        if (allfds[i].fd >= 0)
          CLOSE_FD(i);
      }
    }
  }
}

static void proceed_tcp(struct timespec *polled_at) {
  for (int i = FD_MAX; i < maxfd; i++) {
    int sock = allfds[i].fd;
    short ev = allfds[i].revents;
    if ((sock < 0) || !ev)
      continue;
    LOGMSG("slot#%d sock=%d event=%d", i, sock, ev);
    int seq = tcpseq[i];
    if (seq >= 0) {
      if (seq < MAXSEQ) { // ping tcp-mode
        net_tcp_parse(sock, seq, ev == POLLOUT, polled_at);
        CLOSE_FD(i);
      }
#ifdef WITH_IPINFO
      else { // ipinfo tcp-origin
        allfds[i].revents = 0;  // clear trigger
        if (ev == POLLIN)
          ipinfo_parse(sock, seq);
        else if (ev == POLLOUT) {
          ipinfo_seq_ready(seq);
          allfds[i].events = POLLIN;
        }
      }
#endif
    } else
      LOGMSG("no sequence for tcp sock=%d in slot#%d", sock, i);
  }
}

#define PL_GETTIME(tspec) { if (clock_gettime(CLOCK_MONOTONIC, (tspec)) < 0) { \
  keep_error(errno, __func__); return false; }}

static bool svc(struct timespec *last, const struct timespec *interval, int *timeout) {
  // set 'last' and 'timeout [msec]', return false if it neeeds to stop
  struct timespec now, tv;
  PL_GETTIME(&now);
  timespecadd(last, interval, &tv);

  if (timespeccmp(&now, &tv, >)) {
    *last = now;
    if (grace != GRACE_START) {
      if ((run_opts.cycles > 0) && (numpings >= run_opts.cycles)) {
        grace = GRACE_START;
        grace_started = now;
      }
      if (!grace) { // send batch unless grace period
        int rc = net_send_batch();
        if (rc > 0) {
          numpings++;
          LOGMSG("cycle=%ld", numpings);
        } else if (rc < 0) // fail
          return false;
      }
    }
  }

  if (grace == GRACE_START) {
    timespecsub(&now, &grace_started, &tv);
    if (timespeccmp(&tv, &GRACETIME, >))
      return false;
  }

  struct timespec tout;
  timespecsub(&now, last, &tout);
  timespecsub(interval, &tout, &tout);
  *timeout = time2msec(tout); // in msec
  return true;
}

// proceed keyboard events and return action
static key_action_t keyboard_events(key_action_t action) {
  LOGMSG("action=%d", action);
  switch (action) {
    case ActionQuit:
      LOGMSG("%s", "quit");
      break;
    case ActionReset:
      LOGMSG("%s", "reset network counters");
      net_reset();
      break;
#ifdef CURSESMODE
    case ActionDisplay: {
      int mode = (curses_mode + 1) % curses_mode_max;
      LOGMSG("switch display mode: %d -> %d", curses_mode, mode);
      curses_mode = mode;
      run_opts.chart = mode & 3; // chart bits
      OPT_SUM(chart);
      display_clear();
    } break;
#endif
    case ActionClear:
      LOGMSG("%s", "clear display");
      display_clear();
      break;
    case ActionPauseResume:
      LOGMSG("%s", "'pause/resume' pressed");
      run_opts.pause = !run_opts.pause;
      OPT_SUM(pause);
      break;
    case ActionJitter: // latency OR jitter
      run_opts.jitter = !run_opts.jitter;
      OPT_SUM(jitter);
      onoff_jitter();
      break;
#ifdef WITH_MPLS
    case ActionMPLS:
      LOGMSG("toggle %s: %d -> %d", "MPLS", run_opts.mpls, !run_opts.mpls);
      run_opts.mpls = !run_opts.mpls;
      OPT_SUM(mpls);
      display_clear();
      break;
#endif
#ifdef ENABLE_DNS
    case ActionDNS:
      LOGMSG("toggle %s: %d -> %d", "DNS", run_opts.dns, !run_opts.dns);
      run_opts.dns = !run_opts.dns;
      OPT_SUM(dns);
      dns_open();
      break;
#endif
    case ActionCache:
      LOGMSG("toggle %s: %d -> %d", "cache-mode", run_opts.cache, !run_opts.cache);
      run_opts.oncache = !run_opts.oncache;
      OPT_SUM(oncache);
      break;
#ifdef WITH_IPINFO
    case ActionAS:
    case ActionII:
      LOGMSG("toggle %s", "ipinfo-mode");
      ipinfo_action(action);
      run_opts.asn = run_opts.ipinfo = false;
      if (run_opts.lookup) {
        if (action == ActionAS)
          run_opts.asn    = true;
        else
          run_opts.ipinfo = true;
      }
      OPT_SUM(asn);
      OPT_SUM(ipinfo);
      OPT_SUM(lookup);
      break;
#endif
#if defined(CURSESMODE) || defined(SPLITMODE)
    case ActionScrollDown: {
      LOGMSG("scroll down %d lines", SCROLL_LINES);
      display_offset += SCROLL_LINES;
      int hops = net_max() - net_min();
      if (display_offset >= hops)
        display_offset = hops - 1;
    } break;
    case ActionScrollUp: {
      LOGMSG("scroll up %d lines", SCROLL_LINES);
      int rest = display_offset % 5;
      display_offset -= rest ? rest : SCROLL_LINES;
      if (display_offset < 0)
        display_offset = 0;
    } break;
#endif
    case ActionUDP:
    case ActionTCP:
      run_opts.udp = run_opts.tcp = false;
      if (mtrtype != IPPROTO_ICMP)
        net_set_type(IPPROTO_ICMP);
      else {
        bool udp = (action == ActionUDP);
        net_set_type(udp ? IPPROTO_UDP : IPPROTO_TCP);
        if (udp) run_opts.udp = true;
        else     run_opts.tcp = true;
      }
      OPT_SUM(udp);
      OPT_SUM(tcp);
#ifdef ENABLE_IPV6
      if (af == AF_INET6)
        net_setsock6();
#endif
      break;
    default:
      action = ActionNone;
  }
  return action;
}

#ifdef WITH_IPINFO
static void proceed_ipinfo(void) {
  switch (display_mode) {
    case DisplayReport:
#ifdef OUTPUT_FORMAT_TXT
    case DisplayTXT:
#endif
#ifdef OUTPUT_FORMAT_CSV
    case DisplayCSV:
#endif
#ifdef OUTPUT_FORMAT_JSON
    case DisplayJSON:
#endif
#ifdef OUTPUT_FORMAT_XML
    case DisplayXML:
#endif
      LOGMSG("%s", "query extra IP info");
      query_ipinfo();
      break;
    default: break;
  }
}
#endif

static inline bool tcpish(void) {
  return ((maxfd > FD_MAX) && (
    (mtrtype == IPPROTO_TCP)
#ifdef WITH_IPINFO
    || ipinfo_tcpmode
#endif
  ));
}

// work out events
static int conclude(struct timespec *polled_at) {
  int rc = ActionNone;
  if (IN_ISSET(FD_STDIN)) { // check keyboard events
    LOGMSG("got %s", "stdin event");
    key_action_t act = display_key_action();
    if (act != ActionNone) {
      act = keyboard_events(act);
      if (act == ActionQuit) return act;
      if (act == ActionPauseResume) rc = act;
    }
  }
  if (IN_ISSET(FD_NET)) { // net packet
    LOGMSG("got %s", "icmp or udp response");
    net_icmp_parse(polled_at);
  }
#ifdef ENABLE_DNS
  if (need_dns) { // dns lookup
    if (IN_ISSET(FD_DNS)) {
      LOGMSG("got %s", "dns response");
      dns_parse(allfds[FD_DNS].fd, AF_INET);
    }
#ifdef ENABLE_IPV6
    if (IN_ISSET(FD_DNS6)) {
      LOGMSG("got %s", "dns6 response");
      dns_parse(allfds[FD_DNS6].fd, AF_INET6);
    }
#endif
  }
#endif
  if (tcpish())
    proceed_tcp(polled_at);
  return rc;
}

static bool seqfd_init(void) {
  size_t size = FD_MAX * sizeof(int);
  tcpseq = malloc(size);
  if (!tcpseq) {
    WARN("seq malloc(%zd)", size);
    return false;
  }
  memset(tcpseq, -1, size);
  //
  size = FD_MAX * sizeof(struct pollfd);
  allfds = malloc(size);
  if (!allfds) {
    WARN("fd malloc(%zd)", size);
    free(tcpseq);
    tcpseq = NULL;
    return false;
  }
  for (int i = 0; i < FD_MAX; i++) {
    allfds[i].fd = -1;
    allfds[i].events = POLLIN;
  }
  maxfd = FD_MAX;
  return true;
}

static void seqfd_free(void) {
  poll_close_tcpfds();
  free(allfds);
  allfds = NULL;
  free(tcpseq);
  tcpseq = NULL;
  maxfd = 0;
}

// main loop
int poll_loop(void) {
  LOGMSG("%s", "start");
  if (!seqfd_init())
    return false;
  int anyset = ActionNone;
  bool paused = false;
  numpings = 0;
  grace = NO_GRACE;
  memset(&grace_started, 0, sizeof(grace_started));

  struct timespec lasttime;
  PL_GETTIME(&lasttime);

  while (1) {
    set_fds();

    struct timespec interval;
    waitspec(&interval);
    int timeout = 0, rv = 0;
    do {
      if ((anyset != ActionNone) || paused) {
        timeout = paused ? PAUSE_MSEC : 0;
        if (paused && run_opts.interactive)
          display_redraw();
      } else {
        display_redraw();
#ifdef WITH_IPINFO
        if (ipinfo_ready())
          proceed_ipinfo();
#endif
        if (!svc(&lasttime, &interval, &timeout)) {
          seqfd_free();
          LOGMSG("%s", "done all pings");
          return true;
        }
      }
      if (!timeout)
        usleep(MINSLEEP_USEC);
      rv = poll(allfds, maxfd, timeout);
    } while ((rv < 0) && (errno == EINTR));

    static struct timespec polled_now;
    PL_GETTIME(&polled_now);

    if (rv < 0) {
      int e = errno;
      display_close(true);
      const char* str = rstrerror(e);
      WARN("%s", str);
      LOGMSG("%s", str);
      break;
    }
    if (rv) {
      anyset = conclude(&polled_now);
      if (anyset == ActionQuit)
        break;
      if (anyset == ActionPauseResume) {
        paused = !paused;
        if (!paused)
          anyset = ActionNone;
      }
    } else if (tcpish())
      tcp_timedout(); // not waiting for TCP ETIMEDOUT
  }

  seqfd_free();
  LOGMSG("%s", "finish");
  return true;
}

