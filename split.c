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

#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <termios.h>
#include <math.h>

#include "net.h"
#include "display.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif
#include "split.h"

#define SPLIT_SEP	'\t'

void split_redraw(void) {
  const char fields[] = "LRSBAW"; // Loss, Recv, Sent, Best, Avg, Worst
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    ip_t *addr = &CURRENT_IP(at);
    printf("%2d", at + 1);
    if (addr_exist(addr)) {
#ifdef ENABLE_DNS
      const char *name = dns_ptr_lookup(at, host[at].current);
      printf("%c%s", SPLIT_SEP, name ? name : strlongip(addr));
      if (show_ips)
#endif
        printf("%c%s", SPLIT_SEP, strlongip(addr));
      for (int i = 0; i < sizeof(fields); i++) {
        const char *str = net_elem(at, fields[i]);
        if (str) printf("%c%s", SPLIT_SEP, str);
      }
#ifdef WITH_IPINFO
      if (ipinfo_ready())
        printf("%c%s", SPLIT_SEP, sep_ipinfo(at, host[at].current, SPLIT_SEP));
#endif
      printf("\n");

      for (int ndx = 0; ndx < MAXPATH; ndx++) { // multipath
        if (ndx == host[at].current)
          continue; // because already printed
        ip_t *ip = &IP_AT_NDX(at, ndx);
        if (!addr_exist(ip))
          break;
        printf("%2d:%d", at + 1, ndx);
#ifdef ENABLE_DNS
        name = dns_ptr_lookup(at, ndx);
        printf("%c%s", SPLIT_SEP, name ? name : strlongip(ip));
        if (show_ips)
#endif
          printf("%c%s", SPLIT_SEP, strlongip(ip));
#ifdef WITH_IPINFO
        if (ipinfo_ready())
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
    WARN("tcgetattr");
    warnx("non-interactive mode is ON");
    interactive = false;
    return;
  }
  t.c_lflag &= ~ICANON;
  t.c_lflag &= ~ECHO;
  t.c_cc[VMIN] = 1;
  t.c_cc[VTIME] = 0;
  if (tcsetattr(0, TCSANOW, &t) < 0) {
    WARN("tcsetattr");
    interactive = false;
  }
}

void split_close(void) {
  struct termios t;
  if (!interactive)
    return;
  if (tcgetattr(0, &t) < 0) {
    WARN("tcgetattr");
    return;
  }
  t.c_lflag |= ICANON;
  t.c_lflag |= ECHO;
  if (tcsetattr(0, TCSADRAIN, &t))
    WARN("tcsetattr");
}

const char SMODE_HINTS[] =
"Command:\n"
"  h   help\n"
#ifdef ENABLE_DNS
"  n   toggle DNS\n"
#endif
"  p   pause/resume\n"
"  q   quit\n"
"  r   reset all counters\n"
"  t   toggle TCP pings\n"
"  u   toggle UDP pings\n"
#ifdef WITH_IPINFO
"  y   switching IP info\n"
"  z   toggle ASN lookup\n"
#endif
"\n"
"press SPACE to resume... ";

int split_keyaction(void) {
  char c;
  if (read(0, &c, 1) < 0) {
    WARN("read");
    return 0;
  }
  switch (c) {
    case '+': return ActionScrollDown;
    case '-': return ActionScrollUp;
    case 'h':
      printf("%s", SMODE_HINTS);
      fflush(stdout);
      return ActionPauseResume;
#ifdef ENABLE_DNS
    case 'n': return ActionDNS;
#endif
    case 'p': return ActionPauseResume;
    case  3 : // ^C
    case 'q': return ActionQuit;
    case 'r': return ActionReset;
    case 't': return ActionTCP;
    case 'u': return ActionUDP;
#ifdef WITH_IPINFO
    case 'y': return ActionII;
    case 'z': return ActionAS;
#endif
  }
  return 0;
}

