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

#include <err.h>
#include <ctype.h>
#include <termios.h>

#include "config.h"
#include "mtr.h"
#include "split.h"
#include "display.h"
#include "dns.h"
#include "net.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif

#define SPLIT_SEP	'\t'

void split_redraw(void) {
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    ip_t *addr = &CURRENT_IP(at);
    printf("%2d", at + 1);
    if (addr_exist(addr)) {
      const char *name = dns_ptr_lookup(at, host[at].current);
      printf("%c%s", SPLIT_SEP, name ? name : strlongip(addr));
      if (show_ips)
        printf("%c%s", SPLIT_SEP, strlongip(addr));
      printf("%c%.1f", SPLIT_SEP, net_elem(at, 'L') / 1000.);
      printf("%c%d", SPLIT_SEP, host[at].returned);
      printf("%c%d", SPLIT_SEP, host[at].xmit);
      printf("%c%.1f", SPLIT_SEP, host[at].best / 1000.);
      printf("%c%.1f", SPLIT_SEP, host[at].avg / 1000.);
      printf("%c%.1f", SPLIT_SEP, host[at].worst / 1000.);
#ifdef IPINFO
      if (ii_ready())
        printf("%c%s", SPLIT_SEP, sep_ipinfo(at, host[at].current, SPLIT_SEP));
#endif
      printf("\n");

      for (int ndx = 0; ndx < MAXPATH; ndx++) { // multipath
        if (ndx == host[at].current)
          continue; // because already printed
        ip_t *ip = &IP_AT_NDX(at, ndx);
        if (!addr_exist(ip))
          break;
        name = dns_ptr_lookup(at, ndx);
        printf("%2d:%d", at + 1, ndx);
        printf("%c%s", SPLIT_SEP, name ? name : strlongip(ip));
        if (show_ips)
          printf("%c%s", SPLIT_SEP, strlongip(ip));
#ifdef IPINFO
        if (ii_ready())
          printf("%c%s", SPLIT_SEP, sep_ipinfo(at, ndx, SPLIT_SEP));
#endif
        printf("\n");
      }
    } else
      printf("%c%s\n", SPLIT_SEP, UNKN_ITEM);
  }
}

void split_open(void) {
  struct termios t;
  if (tcgetattr(0, &t) < 0) {
    warn("split.open: %s", "tcgetattr()");
    warnx("non-interactive mode is ON");
    interactive = false;
    return;
  }
  t.c_lflag &= ~ICANON;
  t.c_lflag &= ~ECHO;
  t.c_cc[VMIN] = 1;
  t.c_cc[VTIME] = 0;
  if (tcsetattr(0, TCSANOW, &t) < 0) {
    warn("split.open: %s", "tcsetattr()");
    interactive = false;
  }
}

void split_close(void) {
  struct termios t;
  if (!interactive)
    return;
  if (tcgetattr(0, &t) < 0) {
    warn("split.close: %s", "tcgetattr()");
    return;
  }
  t.c_lflag |= ICANON;
  t.c_lflag |= ECHO;
  if (tcsetattr(0, TCSADRAIN, &t))
    warn("split.close: %s", "tcsetattr()");
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
    warn("split.keyaction: %s", "read()");
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
