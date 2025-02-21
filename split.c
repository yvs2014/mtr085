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
#include <termios.h>

#include "common.h"
#include "nls.h"
#include "aux.h"

#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif
#include "split.h"

static const char SPLIT_SEP = '\t';

static inline void split_multipath(int at) {
  for (int i = 0; i < MAXPATH; i++) { // multipath
    if (i == host[at].current) continue; // already printed
    t_ipaddr *ipaddr = &IP_AT_NDX(at, i);
    if (!addr_exist(ipaddr)) break;
    printf("%2d:%d", at + 1, i);
#ifdef ENABLE_DNS
    const char *name = dns_ptr_lookup(at, i);
    printf("%c%s", SPLIT_SEP, name ? name : strlongip(ipaddr));
    if (run_opts.ips)
#endif
    { printf("%c%s", SPLIT_SEP, strlongip(ipaddr)); }
#ifdef WITH_IPINFO
    if (ipinfo_ready()) printf("%c%s", SPLIT_SEP, sep_ipinfo(at, i, SPLIT_SEP));
#endif
    printf("\n");
  }
}

void split_redraw(void) {
  const char fields[] = "LRSBAW"; // Loss, Recv, Sent, Best, Avg, Worst
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    t_ipaddr *ipaddr = &CURRENT_IP(at);
    printf("%2d", at + 1);
    if (addr_exist(ipaddr)) {
#ifdef ENABLE_DNS
      { const char *name = dns_ptr_lookup(at, host[at].current);
        printf("%c%s", SPLIT_SEP, name ? name : strlongip(ipaddr)); }
      if (run_opts.ips)
#endif
      { printf("%c%s", SPLIT_SEP, strlongip(ipaddr)); }
      for (unsigned i = 0; i < sizeof(fields); i++) {
        const char *str = net_elem(at, fields[i]);
        if (str) printf("%c%s", SPLIT_SEP, str);
      }
#ifdef WITH_IPINFO
      if (ipinfo_ready()) printf("%c%s", SPLIT_SEP, sep_ipinfo(at, host[at].current, SPLIT_SEP));
#endif
      printf("\n");
      split_multipath(at);
    } else printf("%c%s\n", SPLIT_SEP, UNKN_ITEM);
  }
}

void split_open(void) {
  struct termios termios;
  if (tcgetattr(0, &termios) < 0) {
    WARN("%s", "tcgetattr()");
    warnx("non-interactive mode is ON");
    run_opts.interactive = false;
    return;
  }
  termios.c_lflag &= ~ICANON;
  termios.c_lflag &= ~ECHO;
  termios.c_cc[VMIN] = 1;
  termios.c_cc[VTIME] = 0;
  if (tcsetattr(0, TCSANOW, &termios) < 0) {
    WARN("%s", "tcsetattr()");
    run_opts.interactive = false;
  }
}

void split_close(void) {
  if (!run_opts.interactive)
    return;
  struct termios termios;
  if (tcgetattr(0, &termios) < 0) {
    WARN("%s", "tcgetattr()");
    return;
  }
  termios.c_lflag |= ICANON;
  termios.c_lflag |= ECHO;
  if (tcsetattr(0, TCSADRAIN, &termios))
    WARN("%s", "tcsetattr()");
}

static void split_help(void) {
  t_cmd_hint cmd[] = {
    {.key = "e", .hint = CMD_E_STR},
    {.key = "j", .hint = CMD_J_STR},
#ifdef WITH_IPINFO
    {.key = "l", .hint = CMD_L_STR},
    {.key = "L", .hint = CMD_LL_STR},
#endif
#ifdef ENABLE_DNS
    {.key = "n", .hint = CMD_N_STR},
#endif
    {.key = "q", .hint = CMD_Q_STR},
    {.key = "r", .hint = CMD_R_STR},
    {.key = "t", .hint = CMD_T_STR},
    {.key = "u", .hint = CMD_U_STR},
    {.key = "x", .hint = CMD_X_STR},
    {.key = "+-",    .hint = CMD_PM_STR},
    {.key = "SPACE", .hint = CMD_SP_STR},
  };
  int indent = 10;
  //
  printf("%s:\n", COMMANDS_STR);
  for (unsigned i = 0; i < ARRAY_SIZE(cmd); i++) {
    int pad = indent - ustrlen(cmd[i].key);
    printf("%s%*s %s\n", cmd[i].key, (pad < 0) ? 0 : pad, "", cmd[i].hint);
  }
  printf("\n");
  printf("%s ... ", ANYCONT_STR);
  fflush(stdout);
}

key_action_t split_keyaction(void) {
  char ch = 0;
  if (read(0, &ch, 1) < 0) {
    WARN("%s", "read()");
    return 0;
  }
  switch (ch) {
    case '+': return ActionScrollDown;
    case '-': return ActionScrollUp;
    case 'e': return ActionMPLS;
    case 'h':
      split_help();
      return ActionPauseResume;
    case 'j': return ActionJitter;
#ifdef WITH_IPINFO
    case 'l': return ActionAS;
    case 'L': return ActionII;
#endif
#ifdef ENABLE_DNS
    case 'n': return ActionDNS;
#endif
    case 'p': return ActionPauseResume;
    case  3 : // ^C
    case 'q': return ActionQuit;
    case 'r': return ActionReset;
    case 't': return ActionTCP;
    case 'u': return ActionUDP;
    case 'x': return ActionCache;
    default: break;
  }
  return ActionNone;
}

