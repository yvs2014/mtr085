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

#include "config.h"
#include "mtr.h"
#include "mtr-poll.h"
#include "dns.h"
#include "net.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif
#include "display.h"

#if defined(LOG_POLL) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_POLL) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "macros.h"

#define SCROLL_LINES 5
#define FD_BATCHMAX 30
// between poll() calls
#define MINSLEEP_USEC 10  // minimal pause, in microseconds
#define PAUSE_MSEC 100    // when pause button is pressed, in milliseconds

long numpings; // global

// base file descriptors
enum { FD_STDIN, FD_NET, FD_DNS,
#ifdef ENABLE_IPV6
FD_DNS6,
#endif
FD_MAX };

static struct pollfd *allfds; // FDs
static int *tcpseq;           // and corresponding sequence indexes from net.c
static int maxfd;
static const struct timespec GRACETIME = { 5, 0 };
static int prev_mtrtype = IPPROTO_ICMP;
static bool need_dns;

#define SET_POLLFD(ndx, sock) { allfds[ndx].fd = sock; allfds[ndx].revents = 0; }
#define IN_ISSET(ndx) ((allfds[ndx].fd >= 0) && ((allfds[ndx].revents & POLLIN) == POLLIN))
#define CLOSE_FD(ndx) { if (tcpseq) tcpseq[ndx] = -1; \
  if (allfds) { close(allfds[ndx].fd); allfds[ndx].fd = -1; allfds[ndx].revents = 0; /*summ*/ sum_sock[1]++;} \
}

static void set_fds() {
  SET_POLLFD(FD_STDIN, interactive ? 0 : -1);
  SET_POLLFD(FD_NET, net_wait());
  need_dns = enable_dns
#ifdef IPINFO
               || enable_ipinfo;
#endif
  SET_POLLFD(FD_DNS, need_dns ? dns_wait(AF_INET) : -1);
#ifdef ENABLE_IPV6
  SET_POLLFD(FD_DNS6, need_dns ? dns_wait(AF_INET6) : -1);
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
void poll_close_tcpfds(void) { if (maxfd > FD_MAX) for (int i = FD_MAX; i < maxfd; i++) if (allfds[i].fd >= 0) CLOSE_FD(i); }

// not relying on ETIMEDOUT close stalled TCP connections
static void tcp_timedout(void) {
  for (int i = FD_MAX; i < maxfd; i++) {
    int seq = tcpseq[i];
    if (seq >= 0) {
      bool timedout =
#ifdef IPINFO
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

static void proceed_tcp(void) {
  for (int i = FD_MAX; i < maxfd; i++) {
    int sock = allfds[i].fd;
    short ev = allfds[i].revents;
    if ((sock < 0) || !ev)
      continue;
    LOGMSG_("slot#%d sock=%d event=%d", i, sock, ev);
    int seq = tcpseq[i];
    if (seq >= 0) {
      if (seq < MAXSEQ) { // ping tcp-mode
        net_tcp_parse(sock, seq, ev == POLLOUT);
        CLOSE_FD(i);
      }
#ifdef IPINFO
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

enum { NO_GRACE, GRACE_START, GRACE_FINISH }; // state of grace period

static bool svc(struct timespec *last, const struct timespec *interval, int *timeout) {
  static int grace = NO_GRACE;
  static struct timespec grace_started;
  // set last,start and timeout(msec), return false it is necessary to stop
  struct timespec now, tv;
  clock_gettime(CLOCK_MONOTONIC, &now);
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
		} else if (re < 0)
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
#if defined(CURSES) || defined(GRAPHCAIRO)
    case ActionDisplay: {
      int new_mode = (curses_mode + 1) % curses_mode_max;
      LOGMSG_("switch display mode: %d -> %d", curses_mode, new_mode);
      curses_mode = new_mode;
      // bits 7,8: display-type
      CLRBIT(iargs, 7);
      CLRBIT(iargs, 8);
      iargs |= (curses_mode & 3) << 7;
    } // no break, next clear
#endif
    case ActionClear:
      LOGMSG("clear display");
      display_clear();
      break;
    case ActionPauseResume:
      LOGMSG("'pause/resume' pressed");
      break;
    case ActionMPLS:
      enable_mpls = !enable_mpls;
      LOGMSG_("toggle MPLS: %d -> %d", !enable_mpls, enable_mpls);
      TGLBIT(iargs, 2);	// 2nd bit: MPLS on/off
      display_clear();
      break;
    case ActionDNS:
      enable_dns = !enable_dns;
      LOGMSG_("toggle DNS: %d -> %d", !enable_dns, enable_dns);
      TGLBIT(iargs, 5);	// 5th bit: DNS on/off
      dns_open();
      break;
    case ActionCache:
      cache_mode = !cache_mode;
      LOGMSG_("toggle cache-mode: %d -> %d", !cache_mode, cache_mode);
      TGLBIT(iargs, 9);	// 9th bit: cache mode
      break;
#ifdef IPINFO
    case ActionAS:
    case ActionII:
      LOGMSG("toggle ipinfo-mode");
      ipinfo_action(action);
      // 3,4 bits: ASN Lookup, IPInfo
      CLRBIT(iargs, 3);
      CLRBIT(iargs, 4);
      if (enable_ipinfo)
        SETBIT(iargs, (action == ActionAS) ? 3 : 4);
      ipinfo_open();
      break;
#endif
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
    case ActionUDP:
    case ActionTCP: {
      int asked = (action == ActionUDP) ? IPPROTO_UDP : IPPROTO_TCP;
      int curr = mtrtype;
      mtrtype = (mtrtype != asked) ? asked : prev_mtrtype;
      prev_mtrtype = curr;
      LOGMSG_("toggle IP protocol: %d -> %d", prev_mtrtype, mtrtype);
      iargs &= ~3;	// CLR bit#0 udp and bit#1 tcp
      if (mtrtype == IPPROTO_UDP)
        SETBIT(iargs, 0)
      else if (mtrtype == IPPROTO_TCP)
        SETBIT(iargs, 1);
#ifdef ENABLE_IPV6
      net_setsocket6();
#endif
    } break;
    default: action = ActionNone;
  }
  return action;
}

#ifdef IPINFO
static void proceed_ipinfo() {
  switch (display_mode) {
    case DisplayReport:
    case DisplayTXT:
    case DisplayCSV:
    case DisplayJSON:
    case DisplayXML:
      LOGMSG("query extra IP info");
      query_ipinfo();
  }
}
#endif

static inline bool tcpish(void) {
  return ((maxfd > FD_MAX) && (
    (mtrtype == IPPROTO_TCP)
#ifdef IPINFO
    || ipinfo_tcpmode
#endif
  ));
}

// work out events
static int conclude(void) {
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
    net_icmp_parse();
  }
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
  if (tcpish())
    proceed_tcp();
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
}

// main loop
void poll_loop(void) {
  LOGMSG("in");
  if (!seqfd_init())
    return;
  bool anyset = false, paused = false;
  numpings = 0;

  struct timespec lasttime;
  clock_gettime(CLOCK_MONOTONIC, &lasttime);

  while (1) {
    set_fds();

    struct timespec interval;
    waitspec(&interval);
    int timeout;
    int rv;

    do {
      if (anyset || paused)
        timeout = paused ? PAUSE_MSEC : 0;
      else {
        if (interactive || (display_mode == DisplaySplit))
          display_redraw();
#ifdef IPINFO
        if (ipinfo_ready())
          proceed_ipinfo();
#endif
        if (!svc(&lasttime, &interval, &timeout)) {
          seqfd_free();
          LOGMSG_("out by '%s'", "done all pings");
          return;
        }
      }
      if (!timeout)
        usleep(MINSLEEP_USEC);
      rv = poll(allfds, maxfd, timeout);
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0) {
      int e = errno;
      display_close(true);
      WARN_("poll: %s", strerror(e));
      LOGMSG_("poll: %s", strerror(e));
      break;
    }
    anyset = rv ? true : false; // something triggered, or not
    if (anyset) {
      int rc = conclude();
      if (rc == ActionQuit)
        break;
      else if (rc == ActionPauseResume)
        paused = !paused;
    } else if (tcpish())
      tcp_timedout(); // not waiting for TCP ETIMEDOUT
#ifdef GRAPHCAIRO
	{ // external triggers
      int ev = display_extra_action();
      if (ev != ActionNone) {
//LOGMSG_("extra=%d", ev);
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
}

