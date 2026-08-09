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

#define DIV_SPLIT '\t'

static void puts_addr(const t_ipaddr *addr) NONNULL(1);
static void puts_addr(const t_ipaddr *addr) {
  char buff[MAX_ADDRSTRLEN] = {0};
  fputs(addr2str(addr, sizeof(buff), buff), stdout);
}

#ifdef WITH_MPLS
static void spl_print_mpls(mpls_data_t *data) {
  if (data && (data->n > 0)) {
    char buff[64] = {0};
    for (int i = 0; i < data->n; i++) {
      putchar(DIV_SPLIT);
      fputs(mpls2str(&data->label[i], sizeof(buff), buff, 0), stdout);
    }
  }
}
#endif

static void spl_print_row(const t_ipaddr *addr, int at, int ndx, void (*print_stat)(int)) NONNULL(1);
static void spl_print_row(const t_ipaddr *addr, int at, int ndx, void (*print_stat)(int)) {
#ifdef ENABLE_DNS
  putchar(DIV_SPLIT);
  const char *name = dns_ptr_lookup(at, ndx);
  if (name)
    fputs(name, stdout);
  else
    puts_addr(addr);
  if (run_opts.both)
#endif
  { putchar(DIV_SPLIT); puts_addr(addr); }
  //
  if (print_stat)
    print_stat(at);
#ifdef WITH_IPINFO
  if (IPINFOED) {
    char info[NAMELEN] = {0};
    ipinfo_data_div(sizeof(info), info, at, (ndx), DIV_SPLIT);
    if (info[0]) {
      putchar(DIV_SPLIT);
      fputs(info, stdout);
    }
  }
#endif
#ifdef WITH_MPLS
  if (run_opts.mpls)
    spl_print_mpls(&MPLS_AT_NDX(at, ndx));
#endif
  putchar('\n');
}

static inline void split_multipath(int at) {
  for (int ndx = 0; ndx < MAXPATH; ndx++) { // multipath
    if (ndx != host[at].current) { // .current is already printed
      t_ipaddr *addr = &IP_AT_NDX(at, ndx);
      if (!addr_exist(addr))
        break;
      printf("%2d:%d", at + 1, ndx);
      spl_print_row(addr, at, ndx, NULL);
    }
  }
}

static void spl_print_stat(int at) {
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (!stat)
      break;
    // if there's no replies, show either packet counters or '?'
    const char *elem = (host[at].recv || strchr("LDRS", stat->key)) ?
      net_elem(at, stat->key) : "?";
    if (elem) {
      putchar(DIV_SPLIT);
      fputs(elem, stdout);
    }
  }
}

void split_redraw(void) {
  if (run_opts.pause)
    return;
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    printf("%2d", at + 1);
    t_ipaddr *addr = &CURRENT_IP(at);
    if (addr_exist(addr)) {
      spl_print_row(addr, at, host[at].current, spl_print_stat);
      split_multipath(at);
    } else {
      putchar(DIV_SPLIT);
      fputs(UNKN_ITEM, stdout);
    }
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
    int space = INDENT - ustrnlen(cmd[i].key, INDENT) + 1;
    printf("%s%*s%s\n", cmd[i].key, (space < 1) ? 1 : space, "", cmd[i].hint);
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

