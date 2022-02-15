/*
    mtr  --  a network diagnostic tool
    Copyright (C) 1997  Matt Kimball

    split.c -- raw output (for inclusion in KDE Network Utilities or others
                         GUI based tools)
    Copyright (C) 1998  Bertrand Leconte <B.Leconte@mail.dotcom.fr>

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

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <termios.h>

#include "mtr.h"
#include "split.h"
#include "display.h"
#include "dns.h"
#include "net.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif

#define SPLIT_SEPARATOR	"\t"

#ifdef IPINFO
static void split_ipinfo_print(ip_t *addr) {
  int i;
  for (i = 0; (i < IPINFO_MAX_ITEMS) && (ipinfo_no[i] >= 0); i++) {
    char *ipinfo = unaddrcmp(addr) ? get_ipinfo(addr, ipinfo_no[i]) : NULL;
    if (!ipinfo) {
      if (ipinfo_no[i] >= ipinfo_max)
        continue;
      ipinfo = UNKN_ITEM;
    }
    printf(SPLIT_SEPARATOR "%s", ipinfo);
  }
}
#endif

void split_redraw(void) {
  int max = net_max();
  int at;
  for (at = net_min() + display_offset; at < max; at++) {
    ip_t *addr = &host[at].addr;
    printf("%2d", at + 1);
    if (unaddrcmp(addr)) {
      const char *name = dns_lookup(addr);
      printf(SPLIT_SEPARATOR "%s", name ? name : strlongip(addr));
      if (show_ips)
        printf(SPLIT_SEPARATOR "%s", strlongip(addr));
      printf(SPLIT_SEPARATOR "%.1f", net_elem(at, 'L') / 1000.);
      printf(SPLIT_SEPARATOR "%d", host[at].returned);
      printf(SPLIT_SEPARATOR "%d", host[at].xmit);
      printf(SPLIT_SEPARATOR "%.1f", host[at].best / 1000.);
      printf(SPLIT_SEPARATOR "%.1f", host[at].avg / 1000.);
      printf(SPLIT_SEPARATOR "%.1f", host[at].worst / 1000.);
#ifdef IPINFO
      if (ii_ready())
        split_ipinfo_print(addr);
#endif
      printf("\n");

      int i;
      for (i = 0; i < MAXPATH; i++) {	// multipath
        ip_t *addrs = &(host[at].addrs[i]);
        if (!addrcmp(addrs, addr))
          continue;
        if (!unaddrcmp(addrs))
          break;
        name = dns_lookup(addrs);
        printf("%2d:%d", at + 1, i);
        printf(SPLIT_SEPARATOR "%s", name ? name : strlongip(addrs));
        if (show_ips)
          printf(SPLIT_SEPARATOR "%s", strlongip(addrs));
#ifdef IPINFO
        if (ii_ready())
          split_ipinfo_print(addrs);
#endif
        printf("\n");
      }
    } else
      printf(SPLIT_SEPARATOR "%s\n", UNKN_ITEM);
  }
}

void split_open(void) {
  struct termios t;
  if (tcgetattr(0, &t) < 0) {
    perror("split_open()");
    return;
  }
  t.c_lflag &= ~ICANON;
  t.c_lflag &= ~ECHO;
  t.c_cc[VMIN] = 1;
  t.c_cc[VTIME] = 0;
  if (tcsetattr(0, TCSANOW, &t) < 0)
    perror("split_open()");
}

void split_close(void) {
  struct termios t;
  if (tcgetattr(0, &t) < 0) {
    perror("split_close()");
    return;
  }
  t.c_lflag |= ICANON;
  t.c_lflag |= ECHO;
  if (tcsetattr(0, TCSADRAIN, &t))
    perror("split_close()");
}

#define SPLIT_HELP_MESSAGE	\
  "Command:\n" \
  "  ?|h     help\n" \
  "  n       toggle DNS on/off\n" \
  "  p|SPACE pause/resume\n" \
  "  q       quit\n" \
  "  r       reset all counters\n" \
  "  t       switch between ICMP ECHO and TCP SYN\n" \
  "  u       switch between ICMP ECHO and UDP datagrams\n"

int split_keyaction(void) {
  char c;
  if (read(0, &c, 1) < 0) {
    perror("split_keyaction()");
    return 0;
  }

  switch (tolower((int)c)) {
    case '?':
    case 'h':
      printf("%s", SPLIT_HELP_MESSAGE);
#ifdef IPINFO
      printf("  y       switching IP Info\n");
      printf("  z       toggle ASN Lookup on/off\n");
#endif
      printf("\npress SPACE to resume... ");
      fflush(stdout);
      return ActionPauseResume;
    case 'n': return ActionDNS;
    case 'p': return ActionPauseResume;
    case 'q': return ActionQuit;
    case 'r': return ActionReset;
    case 't': return ActionTCP;
    case 'u': mtrtype = (mtrtype == IPPROTO_UDP) ? IPPROTO_ICMP : IPPROTO_UDP;
      return ActionNone;
#ifdef IPINFO
    case 'y': return ActionII;
    case 'z': return ActionAS;
#endif
  }
  switch (c) {
    case 3: return ActionQuit;
    case 17:
    case 19:
    case ' ': return ActionPauseResume;
    case '+': return ActionScrollDown;
    case '-': return ActionScrollUp;
  }

  return 0;
}
