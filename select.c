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
#include <errno.h>
#include <sys/time.h>

#include "config.h"
#include "mtr.h"
#include "select.h"
#include "dns.h"
#include "net.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif
#include "display.h"
#include "macros.h"

typedef struct mtrfd { int net; int dns; int dns6; int ipinfo; } mtrfd_t;

// global vars
fd_set wset;
int maxfd;
//
#define WRITEFD_P ((mtrtype == IPPROTO_TCP) ? &wset : NULL)

const struct timeval GRACETIME = { 5, 0 };
static int numpings;

#define SET_MTRFD(fd) { \
  if (fd >= 0) { \
    FD_SET(fd, rset); \
    if (fd >= maxfd) maxfd = fd + 1; \
  } \
}

void set_fds(fd_set *rset, fd_set *wset, mtrfd_t *fd) {
  if (mtrtype == IPPROTO_TCP)
    FD_ZERO(wset);
  FD_ZERO(rset);
  if (interactive)
    SET_MTRFD(0);
  if (enable_dns) {
    fd->dns = dns_wait(AF_INET);
    SET_MTRFD(fd->dns);
#ifdef ENABLE_IPV6
    fd->dns6 = dns_wait(AF_INET6);
    SET_MTRFD(fd->dns6);
#endif
  }
#ifdef IPINFO
  fd->ipinfo = ipinfo_wait();
  SET_MTRFD(fd->ipinfo);
#endif
  fd->net = net_wait();
  SET_MTRFD(fd->net);
}

int timing(struct timeval *last, struct timeval *interval, struct timeval *start, struct timeval *timeout, int grace) {
  // return bool grace, or -1
  int re = grace;
  struct timeval now, tv;
  gettimeofday(&now, NULL);
  timeradd(last, interval, &tv);

  if (timercmp(&now, &tv, >)) {
    *last = now;
    if (!re) {
      if ((numpings >= max_ping) && (!interactive || alter_ping)) {
        re = 1;
        *start = now;
      }
      if (!re && net_send_batch()) // send batch unless grace period
        numpings++;
    }
  }

  if (re) {
    timersub(&now, start, &tv);
    if (timercmp(&tv, &GRACETIME, >))
      return -1;
  }

  timersub(&now, last, timeout);
  timersub(interval, timeout, timeout);
  return re;
}


int chk_kbd_click(bool* paused) { // Has a key been pressed?
  int action = display_keyaction();
  switch (action) {
    case ActionQuit:
      return -1;
      break;
    case ActionReset:
      net_reset();
      break;
#if defined(CURSES) || defined(GRAPHCAIRO)
    case ActionDisplay:
      curses_mode = (curses_mode + 1) % curses_mode_max;
      // bits 7,8: display-type
      CLRBIT(iargs, 7);
      CLRBIT(iargs, 8);
      iargs |= (curses_mode & 3) << 7;
#endif
    case ActionClear:
      display_clear();
      break;
    case ActionPauseResume:
      *paused = !(*paused);
      break;
    case ActionMPLS:
      enable_mpls = !enable_mpls;
      TGLBIT(iargs, 2);	// 2nd bit: MPLS on/off
      display_clear();
      break;
    case ActionDNS:
      enable_dns = !enable_dns;
      TGLBIT(iargs, 5);	// 5th bit: DNS on/off
      dns_open();
      break;
    case ActionCache:
      cache_mode = !cache_mode;
      TGLBIT(iargs, 9);	// 9th bit: cache mode
      break;
#ifdef IPINFO
    case ActionAS:
    case ActionII:
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
      display_offset += 5;
      break;
    case ActionScrollUp:
      display_offset -= 5;
      if (display_offset < 0)
        display_offset = 0;
      break;
    case ActionTCP:
      iargs &= ~3;	// CLR tcp/udp bits
      if (mtrtype == IPPROTO_TCP) {
        mtrtype = IPPROTO_ICMP;
      } else if (net_tcp_init()) {
        mtrtype = IPPROTO_TCP;
        SETBIT(iargs, 1);
      } else {
        warnx("Press any key to continue..");
        getchar();
        display_clear();
      }
      break;
  }
  return 0;
}

#ifdef IPINFO
void display_ipinfo() {
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
      query_ipinfo();
  }
}
#endif


bool something_new(mtrfd_t *fd, fd_set *rset) {
  bool re = false;

  // net packet
  if ((fd->net > 0) && FD_ISSET(fd->net, rset)) {
    net_parse();
    re = true;
  }

  // dns lookup
  if (enable_dns) {
    if ((fd->dns > 0) && FD_ISSET(fd->dns, rset)) {
      dns_parse(fd->dns, AF_INET);
      re = true;
    }
#ifdef ENABLE_IPV6
    if ((fd->dns6 > 0) && FD_ISSET(fd->dns6, rset)) {
      dns_parse(fd->dns6, AF_INET6);
      re = true;
    }
#endif
  }

#ifdef IPINFO
  // ipinfo lookup
  if (ipinfo_ready()) {
    if ((fd->ipinfo > 0) && FD_ISSET(fd->ipinfo, rset)) {
      ipinfo_parse();
      re = true;
    }
  }
#endif

  // tcp data
  if (mtrtype == IPPROTO_TCP)
    if (net_tcp_parse())
      re = true;
  return re;
}


// main loop
void select_loop(void) {
  fd_set rset;
  bool anyset = false, paused = false;
  int rv, graceperiod = 0;
  numpings = 0;

  struct timeval lasttime, startgrace;
  gettimeofday(&lasttime, NULL);
  timerclear(&startgrace);

  while (1) {
    time_t dt = wait_usec(wait_time);
    struct timeval timeout, interval = { dt / 1000000, dt % 1000000 };

    mtrfd_t mtrfd;
    set_fds(&rset, &wset, &mtrfd);

    do {
      if (anyset || paused)
        /* Set timeout to 0.1sec */
        timeout = (struct timeval) { 0, paused ? 100000 : 0 };
        /* While this is almost instantaneous for human operators,
         * it's slow enough for computers to go do something else;
         * this prevents mtr from hogging 100% CPU time on one core
         */
      else {
        if (interactive || (display_mode == DisplaySplit))
          display_redraw();
#ifdef IPINFO
        if (ipinfo_ready())
          display_ipinfo();
#endif
        if ((graceperiod = timing(&lasttime, &interval, &startgrace, &timeout, graceperiod)) < 0)
          return;
      }
      rv = select(maxfd, &rset, WRITEFD_P, NULL, &timeout);
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0)
      ERRR(errno, "select");

    anyset = something_new(&mtrfd, &rset);
    if (FD_ISSET(0, &rset)) { // check keyboard events too
      if (chk_kbd_click(&paused) < 0)
        return;
      anyset = true;
    }
  }
}

