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

#ifndef DNS_H
#define DNS_H

extern bool enable_dns;
extern unsigned dns_queries[];
extern unsigned dns_replies[];

bool dns_open(void);
void dns_close(void);
int dns_wait(int family);
void dns_parse(int fd, int family);
const char *dns_ptr_lookup(int at, int ndx);
int dns_send_query(int at, int ndx, const char *qstr, int type);
char* ip2arpa(ip_t *ip, const char *suff4, const char *suff6);

extern void (*dns_ptr_handler)(int at, int ndx, const char* answer);
extern void (*dns_txt_handler)(int at, int ndx, const char* answer);

// taken from autoconf manual
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <resolv.h>

#endif
