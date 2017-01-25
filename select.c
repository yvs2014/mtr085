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

extern int Interactive;
extern int DisplayMode;
extern int MaxPing;
extern int ForceMaxPing;
extern float WaitTime;
extern unsigned int iargs;

static struct timeval intervaltime;

fd_set writefd, *p_writefd;
int dnsfd;
#ifdef ENABLE_IPV6
  int dnsfd6;
#endif
int maxfd;

#define GRACETIME (5 * 1000*1000)

void select_loop(void) {
  fd_set readfd;
  int netfd;
  int anyset = 0;
  int NumPing = 0;
  int paused = 0;
  struct timeval lasttime, thistime, selecttime;
  struct timeval startgrace;
  int dt;
  int rv; 
  int graceperiod = 0;

  memset(&startgrace, 0, sizeof(startgrace));
  gettimeofday(&lasttime, NULL);

  p_writefd = (mtrtype == IPPROTO_TCP) ? &writefd : NULL;

  while(1) {
    dt = calc_deltatime(WaitTime);
    intervaltime.tv_sec  = dt / 1000000;
    intervaltime.tv_usec = dt % 1000000;

    FD_ZERO(&readfd);
    if (mtrtype == IPPROTO_TCP)
      FD_ZERO(&writefd);

    if(Interactive) {
      FD_SET(0, &readfd);
      if (maxfd == 0)
        maxfd++;
    }

#define SET_DNSFD(fd, family) { \
  fd = dns_waitfd(family); \
  if (fd >= 0) { \
    FD_SET(fd, &readfd); \
    if (fd >= maxfd) \
      maxfd = dnsfd + 1; \
  } else \
    fd = 0; \
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
      if(anyset || paused) {
	/* Set timeout to 0.1s.
	 * While this is almost instantaneous for human operators,
	 * it's slow enough for computers to go do something else;
	 * this prevents mtr from hogging 100% CPU time on one core.
	 */
	selecttime.tv_sec = 0;
	selecttime.tv_usec = paused?100000:0;

	rv = select(maxfd, &readfd, p_writefd, NULL, &selecttime);

      } else {
	if(Interactive) display_redraw();
#ifdef IPINFO
	if (DisplayMode == DisplayReport)
	  if (ii_ready())
            query_ipinfo();
#endif

	gettimeofday(&thistime, NULL);

	if(thistime.tv_sec > lasttime.tv_sec + intervaltime.tv_sec ||
	   (thistime.tv_sec == lasttime.tv_sec + intervaltime.tv_sec &&
	    thistime.tv_usec >= lasttime.tv_usec + intervaltime.tv_usec)) {
	  lasttime = thistime;

	  if (!graceperiod) {
	    if (NumPing >= MaxPing && (!Interactive || ForceMaxPing)) {
	      graceperiod = 1;
	      startgrace = thistime;
	    }

	    /* do not send out batch when we've already initiated grace period */
	    if (!graceperiod && net_send_batch())
	      NumPing++;
	  }
	}

	if (graceperiod) {
	  dt = (thistime.tv_usec - startgrace.tv_usec) +
		    1000000 * (thistime.tv_sec - startgrace.tv_sec);
	  if (dt > GRACETIME)
	    return;
	}

	selecttime.tv_usec = (thistime.tv_usec - lasttime.tv_usec);
	selecttime.tv_sec = (thistime.tv_sec - lasttime.tv_sec);
	if (selecttime.tv_usec < 0) {
	  --selecttime.tv_sec;
	  selecttime.tv_usec += 1000000;
	}
	selecttime.tv_usec = intervaltime.tv_usec - selecttime.tv_usec;
	selecttime.tv_sec = intervaltime.tv_sec - selecttime.tv_sec;
	if (selecttime.tv_usec < 0) {
	  --selecttime.tv_sec;
	  selecttime.tv_usec += 1000000;
	}

	rv = select(maxfd, &readfd, p_writefd, NULL, &selecttime);
      }
    } while ((rv < 0) && (errno == EINTR));

    if (rv < 0) {
      perror ("Select failed");
      exit (1);
    }
    anyset = 0;

    /*  Have we got new packets back?  */
    if (FD_ISSET(netfd, &readfd)) {
      net_process_return();
      anyset = 1;
    }

    /*  Have we finished a nameservice lookup?  */
    if (enable_dns) {
      if (dnsfd && FD_ISSET(dnsfd, &readfd)) {
        dns_ack(dnsfd, AF_INET);
        anyset = 1;
      }
#ifdef ENABLE_IPV6
      if (dnsfd6 && FD_ISSET(dnsfd6, &readfd)) {
        dns_ack(dnsfd6, AF_INET6);
        anyset = 1;
      }
#endif
    }

#ifdef IPINFO
    if (ii_waitfd())
      if (FD_ISSET(iifd, &readfd)) {
        ii_ack();
        anyset = 1;
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
          display_mode = (display_mode + 1) % display_mode_max;
          // bits 2,3
          iargs |= (display_mode & 3) << 2;
#endif
        case ActionClear:
          display_clear();
          break;
        case ActionPauseResume:
          paused = !paused;
          break;
        case ActionMPLS:
          enablempls = !enablempls;
          display_clear();
          break;
        case ActionDNS:
          enable_dns = !enable_dns;
          dns_open();
          display_clear();
          break;
#ifdef IPINFO
        case ActionAS:
        case ActionII:
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
      anyset = 1;
    }
  }
  return;
}

