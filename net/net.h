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

#ifndef NET_H
#define NET_H

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#ifdef ENABLE_IPV6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include "common.h"
#include "netdef.h"

// 16bits as [hash:7 at:6 ndx:3] (depends on MAXHOST MAXPATH)
#define IDMASK    (0xFE00)
#define AT2ID(n)  (((n) & 0x003F) << 3)
#define ID2AT(n)  (((n) >> 3) & 0x003F)
#define ID2NDX(n) ((n) & 0x7)

#define NETELEM_MAXLEN 16

enum IPV6_ENDIS { IPV6_UNDEF = -1, IPV6_DISABLED = 0, IPV6_ENABLED = 1 };

void net_settings(enum IPV6_ENDIS ipv6_enabled);
void net_assert(void);
void net_protoset(int type);
bool net_set_host(const t_ipaddr *ipaddr) NONNULL(1);
bool net_set_ifaddr(const char *ifaddr) NONNULL(1);
void net_reset(void);
void net_close(void);
int net_wait(void);
bool net_timedout(int seq);
void net_icmp_parse(struct timespec *recv_at) NONNULL(1);
void net_tcp_parse(int sock, int seq, int noerr, struct timespec *recv_at) NONNULL(4);
int net_min(void);
int net_max(void);
const char *net_elem(int at, char key);
int net_send_batch(void);
void net_end_transit(void);
int net_color(int at);

extern bool reset_pattern;
extern bool reset_pldsize;

const char* addr2str(const t_ipaddr *addr, size_t size, char buff[size]) NONNULL(1, 3);
#ifdef WITH_MPLS
const char *mpls2str(const mpls_label_t *label,
  size_t size, char buff[size], uint indent) NONNULL(1, 3);
#endif
uint16_t str2hint(const char* str, uint16_t at, uint16_t ndx);
void waitspec(struct timespec *tv);

#endif
