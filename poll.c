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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "config.h"
#if defined(LOG_POLL) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_POLL) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "common.h"

#include "mtr-poll.h"
#include "net.h"
#include "display.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#if defined(CURSESMODE) || defined(SPLITMODE) || defined(GRAPHMODE)
#define SCROLL_LINES 5
#endif

#define FD_BATCHMAX 30
// between poll() calls
#define MINSLEEP_USEC 10  // minimal pause, in microseconds
#define PAUSE_MSEC 100    // when pause button is pressed, in milliseconds

long numpings; // global

// base file descriptors
enum { FD_STDIN, FD_NET,
#ifdef ENABLE_DNS
       FD_DNS,
#ifdef ENABLE_IPV6
       FD_DNS6,
#endif
#endif
FD_MAX };

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

static void set_fds() {
  SET_POLLFD(FD_STDIN, interactive ? 0 : -1);
  SET_POLLFD(FD_NET, net_wait());
#ifdef ENABLE_DNS
  need_dns = enable_dns
#ifdef WITH_IPINFO
          || enable_ipinfo
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
      LOGMSG_("sock=%d found in slot #%d", sock, i);
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
      LOGMSG_("sock=%d seq=%d put in slot #%d", sock, seq, i);
      return i;
    }
  return -1;
}

static bool allocate_more_memory(void) {
  size_t szi = (maxfd + FD_BATCHMAX) * sizeof(int);
  void *mem = realloc(tcpseq, szi);
  if (!mem) {
    WARN_("seq realloc(%zd)", szi);
    return false;
  }
  tcpseq = (int*)mem;
  memset(&tcpseq[maxfd], -1, FD_BATCHMAX * sizeof(int));
  //
  size_t sz = (maxfd + FD_BATCHMAX) * sizeof(struct pollfd);
  mem = realloc(allfds, sz);
  if (!mem) {
    WARN_("fd realloc(%zd)", sz);
    return false;
  }
  allfds = (struct pollfd *)mem;
  memset(&allfds[maxfd], -1, FD_BATCHMAX * sizeof(struct pollfd));
  maxfd += FD_BATCHMAX;
  LOGMSG_("%zd bytes for %d slots added to pool", szi + sz, FD_BATCHMAX);
  return true;
}

int poll_reg_fd(int sock, int seq) {
  int slot = sock_already_accounted(sock);
  if (slot < 0) {
    if ((slot = save_in_vacant_slot(sock, seq)) < 0) {
      if (allocate_more_memory()) {
        if ((slot = save_in_vacant_slot(sock, seq)) < 0)
          LOGMSG_("sock=%d: assertion failed", sock);
      } else
        LOGMSG_("sock=%d: memory allocation failed", sock);
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
    LOGMSG_("slot#%d sock=%d event=%d", i, sock, ev);
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
      LOGMSG_("no sequence for tcp sock=%d in slot#%d", sock, i);
  }
}

static bool svc(struct timespec *last, const struct timespec *interval, int *timeout) {
  // set 'last' and 'timeout [msec]', return false if it neeeds to stop
  struct timespec now, tv;
  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
    FAIL_CLOCK_GETTIME;
  timespecadd(last, interval, &tv);

  if (timespeccmp(&now, &tv, >)) {
    *last = now;
    if (grace != GRACE_START) {
      if ((max_ping > 0) && (numpings >= max_ping)) {
        grace = GRACE_START;
        grace_started = now;
      }
      if (!grace) { // send batch unless grace period
        int re = net_send_batch();
        if (re > 0) {
          numpings++;
          LOGMSG_("cycle=%ld", numpings);
        } else if (re < 0) // fail
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
static int keyboard_events(int action) {
  LOGMSG_("action=%d", action);
  switch (action) {
    case ActionQuit:
      LOGMSG("quit");
      break;
    case ActionReset:
      LOGMSG("reset network counters");
      net_reset();
      break;
#if defined(CURSESMODE) || defined(GRAPHMODE)
    case ActionDisplay: {
      int cm = (curses_mode + 1) % curses_mode_max;
      LOGMSG_("switch display mode: %d -> %d", curses_mode, cm);
      curses_mode = cm;
      // chart bits
      CLRBIT(run_args, RA_DM0);
      CLRBIT(run_args, RA_DM1);
      if (curses_mode & 1) SETBIT(run_args, RA_DM0);
      if (curses_mode & 2) SETBIT(run_args, RA_DM1);
      display_clear();
    } break;
#endif
    case ActionClear:
      LOGMSG("clear display");
      display_clear();
      break;
    case ActionPauseResume:
      TGLBIT(run_args, RA_PAUSE);
      LOGMSG("'pause/resume' pressed");
      break;
#ifdef WITH_MPLS
    case ActionMPLS:
      enable_mpls = !enable_mpls;
      LOGMSG_("toggle MPLS: %d -> %d", !enable_mpls, enable_mpls);
      TGLBIT(run_args, RA_MPLS);
      display_clear();
      break;
#endif
#ifdef ENABLE_DNS
    case ActionDNS:
      enable_dns = !enable_dns;
      LOGMSG_("toggle DNS: %d -> %d", !enable_dns, enable_dns);
      TGLBIT(run_args, RA_DNS);
      dns_open();
      break;
#endif
    case ActionCache:
      cache_mode = !cache_mode;
      LOGMSG_("toggle cache-mode: %d -> %d", !cache_mode, cache_mode);
      TGLBIT(run_args, RA_CACHE);
      break;
#ifdef WITH_IPINFO
    case ActionAS:
    case ActionII:
      LOGMSG("toggle ipinfo-mode");
      ipinfo_action(action);
      CLRBIT(run_args, RA_ASN);
      CLRBIT(run_args, RA_IPINFO);
      if (enable_ipinfo)
        SETBIT(run_args, (action == ActionAS) ? RA_ASN : RA_IPINFO);
      break;
#endif
#if defined(CURSESMODE) || defined(SPLITMODE) || defined(GRAPHMODE)
    case ActionScrollDown: {
      LOGMSG_("scroll down %d lines", SCROLL_LINES);
      display_offset += SCROLL_LINES;
      int hops = net_max() - net_min();
      if (display_offset >= hops)
        display_offset = hops - 1;
    } break;
    case ActionScrollUp: {
      LOGMSG_("scroll up %d lines", SCROLL_LINES);
      int rest = display_offset % 5;
      display_offset -= rest ? rest : SCROLL_LINES;
      if (display_offset < 0)
        display_offset = 0;
    } break;
#endif
    case ActionUDP:
    case ActionTCP:
      CLRBIT(run_args, RA_UDP); CLRBIT(run_args, RA_TCP);
      if (mtrtype != IPPROTO_ICMP) net_set_type(IPPROTO_ICMP);
      else {
        net_set_type((action == ActionUDP) ? IPPROTO_UDP : IPPROTO_TCP);
        SETBIT(run_args, (action == ActionUDP) ? RA_UDP : RA_TCP);
      }
#ifdef ENABLE_IPV6
      net_setsocket6();
#endif
      break;
    default: action = ActionNone;
  }
  return action;
}

#ifdef WITH_IPINFO
static void proceed_ipinfo() {
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
      LOGMSG("query extra IP info");
      query_ipinfo();
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
    LOGMSG("got stdin event");
    int ev = display_key_action();
    if (ev != ActionNone) {
      ev = keyboard_events(ev);
      if (ev == ActionQuit)
        return ev; // return immediatelly if 'quit' is pressed
      else if (ev == ActionPauseResume)
        rc = ev;
    }
  }
  if (IN_ISSET(FD_NET)) { // net packet
    LOGMSG("got icmp or udp response");
    net_icmp_parse(polled_at);
  }
#ifdef ENABLE_DNS
  if (need_dns) { // dns lookup
    if (IN_ISSET(FD_DNS)) {
      LOGMSG("got dns response");
      dns_parse(allfds[FD_DNS].fd, AF_INET);
    }
#ifdef ENABLE_IPV6
    if (IN_ISSET(FD_DNS6)) {
      LOGMSG("got dns6 response");
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
  size_t sz = FD_MAX * sizeof(int);
  tcpseq = malloc(sz);
  if (!tcpseq) {
    WARN_("seq malloc(%zd)", sz);
    return false;
  }
  memset(tcpseq, -1, sz);
  //
  sz = FD_MAX * sizeof(struct pollfd);
  allfds = malloc(sz);
  if (!allfds) {
    WARN_("fd malloc(%zd)", sz);
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
  LOGMSG("start");
  if (!seqfd_init())
    return false;
  bool anyset = false, paused = false;
  numpings = 0;
  grace = NO_GRACE;
  memset(&grace_started, 0, sizeof(grace_started));

  struct timespec lasttime;
  if (clock_gettime(CLOCK_MONOTONIC, &lasttime) < 0)
    FAIL_CLOCK_GETTIME;

  while (1) {
    set_fds();

    struct timespec interval;
    waitspec(&interval);
    int timeout;
    int rv;

    do {
      if (anyset || paused) {
        timeout = paused ? PAUSE_MSEC : 0;
        if (paused && interactive)
          display_redraw();
      } else {
        if (interactive || (display_mode == DisplaySplit))
          display_redraw();
#ifdef WITH_IPINFO
        if (ipinfo_ready())
          proceed_ipinfo();
#endif
        if (!svc(&lasttime, &interval, &timeout)) {
          seqfd_free();
          LOGMSG("done all pings");
          return true;
        }
      }
      if (!timeout)
        usleep(MINSLEEP_USEC);
      rv = poll(allfds, maxfd, timeout);
    } while ((rv < 0) && (errno == EINTR));

    static struct timespec polled_now;
    if (clock_gettime(CLOCK_MONOTONIC, &polled_now) < 0)
      FAIL_CLOCK_GETTIME; // break;

    if (rv < 0) {
      int e = errno;
      display_close(true);
      WARN_("poll: %s", strerror(e));
      LOGMSG_("poll: %s", strerror(e));
      break;
    }
    anyset = rv ? true : false; // something triggered, or not
    if (anyset) {
      int rc = conclude(&polled_now);
      if (rc == ActionQuit)
        break;
      else if (rc == ActionPauseResume)
        paused = !paused;
    } else if (tcpish())
      tcp_timedout(); // not waiting for TCP ETIMEDOUT
#ifdef GRAPHMODE
    { // external triggers
      int ev = display_extra_action();
      if (ev != ActionNone) {
        ev = keyboard_events(ev);
        if (ev == ActionQuit)
          break;
        else if (ev == ActionPauseResume)
          paused = !paused;
      }
    }
#endif
  }

  seqfd_free();
  LOGMSG("finish");
  return true;
}

