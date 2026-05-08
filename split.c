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

#ifdef WITH_MPLS
static void spl_print_mpls(mpls_data_t *data) {
  if (data && data->n > 0) {
    printf("%c[%s", DIV_SPLIT, mpls2str(&data->label[1], 0));
    for (int i = 1; i < data->n; i++)
      printf(", %s", mpls2str(&data->label[i], 0));
    putchar(']');
  }
}
#define SPL_PRINT_MPLS(data) do { if (run_opts.mpls) spl_print_mpls(data); } while (0);
#else
#define SPL_PRINT_MPLS(data) NOOP
#endif

#ifdef WITH_IPINFO
#define SPL_PRINT_IPINFO(ndx) do { if (IPINFOED) {           \
  char info[NAMELEN] = {0};                                  \
  ipinfo_data_div(info, sizeof(info), at, (ndx), DIV_SPLIT); \
  if (info[0]) printf("%c%s", DIV_SPLIT, info);              \
}} while (0);
#else
#define SPL_PRINT_IPINFO(ndx) NOOP
#endif

#define SPL_GET_ADDRSTR           \
  char str[MAX_ADDRSTRLEN] = {0}; \
  const char *addr = inet_ntop(af, ipaddr, str, sizeof(str)); /* TODO: str cache */ \
  if (!addr) addr = UNKN_ITEM;    \

static void spl_print_row(const t_ipaddr *ipaddr, int at, int ndx, void (*print_stat_fn)(int)) NONNULL(1);
static void spl_print_row(const t_ipaddr *ipaddr, int at, int ndx, void (*print_stat_fn)(int)) {
  SPL_GET_ADDRSTR;
#ifdef ENABLE_DNS
  const char *name = dns_ptr_lookup(at, ndx);
  printf("%c%s", DIV_SPLIT, name ? name : addr);
  if (run_opts.both)
#endif
  { printf("%c%s", DIV_SPLIT, addr); }
  //
  if (print_stat_fn) print_stat_fn(at);
  SPL_PRINT_IPINFO(ndx);
  SPL_PRINT_MPLS(&MPLS_AT_NDX(at, ndx));
  putchar('\n');
}

static inline void split_multipath(int at) {
  for (int ndx = 0; ndx < MAXPATH; ndx++) { // multipath
    if (ndx == host[at].current) continue; // already printed
    t_ipaddr *ipaddr = &IP_AT_NDX(at, ndx);
    if (addr_exist(ipaddr)) {
      printf("%2d:%d", at + 1, ndx);
      spl_print_row(ipaddr, at, ndx, NULL);
    }
  }
}

static void spl_print_stat(int at) {
  for (uint i = 0; i < MAXFLD; i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    // if there's no replies, show either packet counters or '?'
    const char *elem = (host[at].recv || strchr("LDRS", stat->key)) ? net_elem(at, stat->key) : "?";
    if (elem) printf("%c%s", DIV_SPLIT, elem);
  }
}

void split_redraw(void) {
  if (run_opts.pause)
    return;
  int max = net_max();
  for (int at = net_min() + display_offset; at < max; at++) {
    printf("%2d", at + 1);
    t_ipaddr *ipaddr = &CURRENT_IP(at);
    if (addr_exist(ipaddr)) {
      spl_print_row(ipaddr, at, host[at].current, spl_print_stat);
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

static key_action_t spl_key_h(void) {
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
  return ActionPauseResume;
}

static key_action_t spl_key_p(void) {
  if (run_opts.pause)
    putchar('\n');
  else {
    printf("%s ... ", ANYLTTR_STR);
    (void)fflush(stdout);
  }
  return ActionPauseResume;
}

static key_action_t spl_key_q(void) {
  if (run_opts.pause)
    putchar('\n');
  return ActionQuit;
}

typedef key_action_t (*spl_key_fn)(void);

// map: SPLIT local extra actions
static spl_key_fn spl_actfn_map[UINT8_MAX] =  {
  ['?']     = spl_key_h, // help
  ['h']     = spl_key_h,
  [' ']     = spl_key_p, // pause/resume
  ['p']     = spl_key_p,
  ['q']     = spl_key_q, // quit
  [3/*^C*/] = spl_key_q,
//[27/*Esc*/] = spl_key_q,
};

// map: char to action
static key_action_t spl_action_map[UINT8_MAX] =  {
#ifdef WITH_MPLS
  ['e'] = ActionMPLS,
#endif
  ['j'] = ActionJitter,
#ifdef WITH_IPINFO
  ['l'] = ActionAS,
  ['L'] = ActionII,
#endif
#ifdef ENABLE_DNS
  ['n'] = ActionDNS,
#endif
  ['r'] = ActionReset,
  ['t'] = ActionTCP,
  ['u'] = ActionUDP,
  ['x'] = ActionCache,
};

key_action_t split_keyaction(void) {
  uint8_t ch = 0;
  if (read(0, &ch, sizeof(ch)) < 0) {
    WARN("%s", "read()");
    return 0;
  }
  if (ch) {
    spl_key_fn fn = spl_actfn_map[ch];
    return fn ? fn() : spl_action_map[ch];
  }
  return ActionNone /*0*/;
}

