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

enum {
  DIV_SPLIT = '\t',
};

static inline void split_multipath(int at) {
  for (int i = 0; i < MAXPATH; i++) { // multipath
    if (i != host[at].current) { // not printed yet
      t_ipaddr *addr = &IP_AT_NDX(at, i);
      if (!addr_exist(addr))
        break;
      //
      printf("%2d:%d", at + 1, i);
#ifdef ENABLE_DNS
      const char *name = dns_ptr_lookup(at, i);
      if (name)
        printf("%c%s", DIV_SPLIT, name);
      else {
        char str[MAX_ADDRSTRLEN] = {0};
        printf("%c%s", DIV_SPLIT, addr2str(addr, sizeof(str), str));
      }
      if (run_opts.both)
#endif
      { char str[MAX_ADDRSTRLEN] = {0};
        printf("%c%s", DIV_SPLIT, addr2str(addr, sizeof(str), str)); }
#ifdef WITH_IPINFO
      if (IPINFOED) {
        char info[NAMELEN] = {0};
        ipinfo_data_div(sizeof(info), info, at, i, DIV_SPLIT);
        if (info[0])
          printf("%c%s", DIV_SPLIT, info);
      }
#endif
      printf("\n");
    }
  }
}

void split_redraw(void) {
  if (run_opts.pause)
    return;
  const char fields[] = "LRSBAW"; // Loss, Recv, Sent, Best, Avg, Worst
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    printf("%2d", at + 1);
    t_ipaddr *addr = &CURRENT_IP(at);
    if (addr_exist(addr)) {
#ifdef ENABLE_DNS
      const char *name = dns_ptr_lookup(at, host[at].current);
      if (name)
        printf("%c%s", DIV_SPLIT, name);
      else {
        char str[MAX_ADDRSTRLEN] = {0};
        printf("%c%s", DIV_SPLIT, addr2str(addr, sizeof(str), str));
      }
      if (run_opts.both)
#endif
      { char str[MAX_ADDRSTRLEN] = {0};
        printf("%c%s", DIV_SPLIT, addr2str(addr, sizeof(str), str)); }
      for (uint i = 0; i < sizeof(fields); i++) {
        const char *elem = net_elem(at, fields[i]);
        if (elem)
          printf("%c%s", DIV_SPLIT, elem);
      }
#ifdef WITH_IPINFO
      if (IPINFOED) {
        char info[NAMELEN] = {0};
        ipinfo_data_div(sizeof(info), info, at, host[at].current, DIV_SPLIT);
        if (info[0])
          printf("%c%s", DIV_SPLIT, info);
      }
#endif
      printf("\n");
      split_multipath(at);
    } else
      printf("%c%s\n", DIV_SPLIT, UNKN_ITEM);
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
#ifdef WITH_IPINFO
    {.key = "y", .hint = CMD_Y_STR},
#endif
    {.key = "SPACE", .hint = CMD_SP_STR},
  };
  //
#define INDENT 10
  printf("%s:\n", COMMANDS_STR);
  for (uint i = 0; i < ARRAY_LEN(cmd); i++) {
    int pad = INDENT - ustrnlen(cmd[i].key, INDENT);
    printf("%s%*s %s\n", cmd[i].key, (pad < 0) ? 0 : pad, "", cmd[i].hint);
  }
#undef INDENT
  printf("\n%s ... ", ANYLTTR_STR);
  (void)fflush(stdout);
}

key_action_t split_keyaction(void) {
  key_action_t rc = ActionNone;
  char ch = 0;
  if (read(0, &ch, 1) < 0)
    WARN("%s", "read()");
  else switch (ch) {
#ifdef WITH_MPLS
    case 'e': rc = ActionMPLS;    break;
#endif
    case 'h':
      split_help();
      rc = ActionPauseResume;
      break;
    case 'j': rc = ActionJitter;  break;
#ifdef WITH_IPINFO
    case 'l': rc = ActionAS;      break;
    case 'L': rc = ActionII;      break;
#endif
#ifdef ENABLE_DNS
    case 'n': rc = ActionDNS;     break;
#endif
    case ' ':
    case 'p':
      if (run_opts.pause)
        putchar('\n');
      else {
        printf("%s ... ", ANYLTTR_STR);
        (void)fflush(stdout);
      }
      rc = ActionPauseResume;
      break;
    case  3 : // ^C
//  case  27: // Esc
    case 'q':
      if (run_opts.pause)
        putchar('\n');
      rc = ActionQuit;
      break;
    case 'r': rc = ActionReset;   break;
    case 't': rc = ActionTCP;     break;
    case 'u': rc = ActionUDP;     break;
    case 'x': rc = ActionCache;   break;
#ifdef WITH_IPINFO
    case 'y': rc = ActionMultiII; break;
#endif
    default: break;
  }
  return rc;
}

