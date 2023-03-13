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

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/select.h>
#include <string.h>
#include <math.h>
#include <errno.h>

#include "mtr.h"
#include "select.h"
#include "dns.h"
#include "net.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif
#include "display.h"

// global vars
fd_set writefd, *p_writefd;
int maxfd;
//

static int dnsfd;
#ifdef ENABLE_IPV6
static int dnsfd6;
#endif

#define GRACETIME (5 * 1000*1000)
static struct timeval gracetime = { GRACETIME, 0 };

#define SET_DNSFD(fd, family) { \
  fd = dns_waitfd(family); \
  if (fd < 0) fd = 0; \
  else { \
    FD_SET(fd, &readfd); \
    if (fd >= maxfd) maxfd = dnsfd + 1; \
  } \
}

void select_loop(void) {
  fd_set readfd;
  int netfd;
  bool anyset = false;
  bool paused = false;
  int ping_no = 0;
  struct timeval lasttime, selecttime;
  struct timeval startgrace;
  time_t dt;
  int rv; 
  bool graceperiod = false;

  memset(&startgrace, 0, sizeof(startgrace));
  gettimeofday(&lasttime, NULL);

  p_writefd = (mtrtype == IPPROTO_TCP) ? &writefd : NULL;

  while(1) {
    dt = calc_deltatime(wait_time);
    static struct timeval intervaltime;
    intervaltime.tv_sec  = dt / 1000000;
    intervaltime.tv_usec = dt % 1000000;

    FD_ZERO(&readfd);
    if (mtrtype == IPPROTO_TCP)
      FD_ZERO(&writefd);

    if (interactive) {
      FD_SET(0, &readfd);
      if (maxfd == 0)
        maxfd++;
    }

    if (enable_dns) {
      SET_DNSFD(dnsfd, AF_INET);
#ifdef ENABLE_IPV6
      SET_DNSFD(dnsfd6, AF_INET6);
#endif
	} else {
      dnsfd = 0;
#ifdef ENABLE_IPV6
      dnsfd6 = 0;
#endif
    }

#ifdef IPINFO
    int iifd;
    if ((iifd = ii_waitfd())) {
      FD_SET(iifd, &readfd);
      if (iifd >= maxfd)
        maxfd = iifd + 1;
    }
#endif

    netfd = net_waitfd();
    FD_SET(netfd, &readfd);
    if(netfd >= maxfd) maxfd = netfd + 1;

    do {
      if (anyset || paused) {
	/* Set timeout to 0.1s.
	 * While this is almost instantaneous for human operators,
	 * it's slow enough for computers to go do something else;
	 * this prevents mtr from hogging 100% CPU time on one core.
	 */
        selecttime = (struct timeval) { 0, paused ? 100000 : 0 };
        rv = select(maxfd, &readfd, p_writefd, NULL, &selecttime);
      } else {
        if (interactive || (display_mode == DisplaySplit))
          display_redraw();
#ifdef IPINFO
        if (ii_ready()) {
          switch (display_mode) {
            case DisplayReport:
#ifdef OUTPUT_FORMAT_CSV
            case DisplayCSV:
#endif
#ifdef OUTPUT_FORMAT_TXT
            case DisplayTXT:
#endif
#ifdef OUTPUT_FORMAT_XML
            case DisplayXML:
#endif
              query_ipinfo();
          }
        }
#endif
        {
          struct timeval now, _tv;
          gettimeofday(&now, NULL);
          timeradd(&lasttime, &intervaltime, &_tv);

          if (timercmp(&now, &_tv, >)) {
            lasttime = now;
            if (!graceperiod) {
              if ((ping_no >= max_ping) && (!interactive || alter_ping)) {
                graceperiod = true;
                startgrace = now;
              }
              /* do not send out batch when we've already initiated grace period */
              if (!graceperiod && net_send_batch())
                ping_no++;
            }
          }

          if (graceperiod) {
            timersub(&now, &startgrace, &_tv);
            if (timercmp(&_tv, &gracetime, >)) {
              dt = timer2usec(&_tv);
              return;
            }
          }

          timersub(&now, &lasttime, &selecttime);
          timersub(&intervaltime, &selecttime, &selecttime);
        }

        rv = select(maxfd, &readfd, p_writefd, NULL, &selecttime);
      }
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0) {
      perror ("Select failed");
      exit (1);
    }
    anyset = false;

    /*  Have we got new packets back?  */
    if (FD_ISSET(netfd, &readfd)) {
      net_process_return();
      anyset = true;
    }

    /*  Have we finished a nameservice lookup?  */
    if (enable_dns) {
      if (dnsfd && FD_ISSET(dnsfd, &readfd)) {
        dns_ack(dnsfd, AF_INET);
        anyset = true;
      }
#ifdef ENABLE_IPV6
      if (dnsfd6 && FD_ISSET(dnsfd6, &readfd)) {
        dns_ack(dnsfd6, AF_INET6);
        anyset = true;
      }
#endif
    }

#ifdef IPINFO
    if (ii_waitfd()) {
      if (FD_ISSET(iifd, &readfd)) {
        ii_ack();
        anyset = true;
      }
    }
#endif

    /* Check for activity on open sockets */
    if (mtrtype == IPPROTO_TCP)
      anyset = net_process_tcp_fds();

    /*  Has a key been pressed?  */
    if (FD_ISSET(0, &readfd)) {
      int action = display_keyaction();
      switch (action) {
        case ActionQuit: 
          return;
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
          paused = !paused;
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
          display_clear();
          break;
#ifdef IPINFO
        case ActionAS:
        case ActionII:
          ii_action(action);
          // 3,4 bits: ASN Lookup, IPInfo
          CLRBIT(iargs, 3);
          CLRBIT(iargs, 4);
          if (enable_ipinfo)
            SETBIT(iargs, (action == ActionAS) ? 3 : 4);
          break;
        case ActionII_Map:
          ii_action(action);
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
            p_writefd = NULL;
          } else if (net_tcp_init()) {
            mtrtype = IPPROTO_TCP;
            p_writefd = &writefd;
            SETBIT(iargs, 1);
          } else {
            fprintf(stderr, "\rPress any key to continue..\r\n");
            getchar();
            display_clear();
          }
          break;
      }
      anyset = true;
    }
  }
  return;
}

