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
#define USLEEP 10 /* minimal polling in microseconds */

enum FD_POLL { FD_STDIN, FD_NET, FD_DNS,
#ifdef ENABLE_IPV6
FD_DNS6,
#endif
#ifdef ENABLE_IPV6
FD_IPINFO,
#endif
FD_MAX };

static struct pollfd *allfds; // FDs
static int *tcpseq;           // and corresponding sequence indexes from net.c
static int maxfd;
static const struct timespec GRACETIME = { 5, 0 };
static long numpings;
static int prev_mtrtype = IPPROTO_ICMP;

#define SET_POLLFD(ndx, sock) { allfds[ndx].fd = sock; allfds[ndx].revents = 0; }
#define IN_ISSET(ndx) ((allfds[ndx].fd >= 0) && ((allfds[ndx].revents & POLLIN) == POLLIN))
#define CLOSE_FD(ndx) { close(allfds[ndx].fd); allfds[ndx].fd = -1; allfds[ndx].revents = 0; tcpseq[ndx] = -1; /*stat*/ sum_sock[1]++;}

static void set_fds() {
  if (interactive)
    SET_POLLFD(FD_STDIN, 0);
  SET_POLLFD(FD_NET, net_wait());
  if (enable_dns) {
    SET_POLLFD(FD_DNS, dns_wait(AF_INET));
#ifdef ENABLE_IPV6
    SET_POLLFD(FD_DNS6, dns_wait(AF_INET6));
#endif
  }
#ifdef IPINFO
  SET_POLLFD(FD_IPINFO, ipinfo_wait());
#endif
  if ((mtrtype == IPPROTO_TCP) && (maxfd > FD_MAX))
    for (int i = FD_MAX; i < maxfd; i++)
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

bool poll_count_on_fd(int sock, int seq) {
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
  return (slot >= 0);
}

void poll_close_tcpfds(void) { if (maxfd > FD_MAX) for (int i = FD_MAX; i < maxfd; i++) if (allfds[i].fd >= 0) CLOSE_FD(i); }

// not relying on ETIMEDOUT close stalled TCP connections
static void tcp_timedout(void) {
  for (int i = FD_MAX; i < maxfd; i++)
    if ((allfds[i].fd >= 0) && (tcpseq[i] >= 0))
      if (net_timedout(tcpseq[i]))
        CLOSE_FD(i);
}

static bool tcpfds(void) {
  bool re = false;
  for (int i = FD_MAX; i < maxfd; i++) {
    int sock = allfds[i].fd;
    if (sock >= 0) {
      if (allfds[i].revents) { /* option: ((allfds[i].revents & POLLOUT) == POLLOUT) */
        LOGMSG_("revents=%d in slot#%d", allfds[i].revents, i);
        int seq = tcpseq[i];
        if (seq >= 0)
          net_tcp_parse(sock, seq, allfds[i].revents == POLLOUT);
        else
          LOGMSG_("no sequence for tcp sock=%d in slot#%d", sock, i);
        CLOSE_FD(i);
      }
    }
  }
  return re;
}

enum GRACE_VALUES { NO_GRACE, GRACE_START, GRACE_FINISH };

static bool svc(struct timespec *last, const struct timespec *interval, int *timeout) {
  static int grace = NO_GRACE;
  static struct timespec grace_started;
  // set last,start and timeout(msec), then return boolean grace or -1
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


static int keyboard_click(bool* paused) { // Has a key been pressed?
  int action = display_keyaction();
  switch (action) {
    case ActionQuit:
      LOGMSG("quit");
      return -1;
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
      *paused = !(*paused);
      LOGMSG_("'%s' pressed", *paused ? "pause" : "resume");
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
    case ActionScrollDown:
      LOGMSG_("scroll down %d lines", SCROLL_LINES);
      display_offset += SCROLL_LINES;
      break;
    case ActionScrollUp:
      LOGMSG_("scroll up %d lines", SCROLL_LINES);
      display_offset -= SCROLL_LINES;
      if (display_offset < 0)
        display_offset = 0;
      break;
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
  }
  return 0;
}

#ifdef IPINFO
void display_ipinfo() {
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


bool polled() {
  bool re = false;
  if (IN_ISSET(FD_NET)) { // net packet
    LOGMSG("got icmp or udp response");
    net_icmp_parse();
    re = true;
  }
  if (enable_dns) { // dns lookup
    if (IN_ISSET(FD_DNS)) {
      LOGMSG("got dns response");
      dns_parse(allfds[FD_DNS].fd, AF_INET);
      re = true;
    }
#ifdef ENABLE_IPV6
    if (IN_ISSET(FD_DNS6)) {
      LOGMSG("got dns6 response");
      dns_parse(allfds[FD_DNS6].fd, AF_INET6);
      re = true;
    }
#endif
  }
#ifdef IPINFO
  if (ipinfo_ready()) { // ipinfo lookup
    if (IN_ISSET(FD_IPINFO)) {
      LOGMSG("got ipinfo response");
      ipinfo_parse();
      re = true;
    }
  }
#endif
  if ((mtrtype == IPPROTO_TCP) && (maxfd > FD_MAX)) {
    if (tcpfds()) // tcp data
      re = true;
  }
  return re;
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
        timeout = paused ? 100 : 0;  // 100 milliseconds polling in pause, if 0 then at least usleep(10 usec) below
      else {
        if (interactive || (display_mode == DisplaySplit))
          display_redraw();
#ifdef IPINFO
        if (ipinfo_ready())
          display_ipinfo();
#endif
        if (!svc(&lasttime, &interval, &timeout)) {
          seqfd_free();
          LOGMSG_("out by '%s'", "done all pings");
          return;
        }
      }
      if (!timeout)
        usleep(USLEEP);
      rv = poll(allfds, maxfd, timeout);
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0) {
      int e = errno;
      display_close(true);
      WARN_("poll: %s", strerror(e));
      LOGMSG_("poll: %s", strerror(e));
      seqfd_free();
      return;
    } else if (!rv && (mtrtype == IPPROTO_TCP) && (maxfd > FD_MAX))
      tcp_timedout(); // not waiting for TCP ETIMEDOUT

    anyset = polled();
    if (IN_ISSET(FD_STDIN)) { // check keyboard too
      if (keyboard_click(&paused) < 0) // i.e. quit
        break;
      anyset = true;
    }
  }

  seqfd_free();
}

