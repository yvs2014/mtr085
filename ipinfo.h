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

#ifndef IPINFO_H
#define IPINFO_H

#include <stdbool.h>

void ii_open(void);
void ii_close(void);
void ii_parsearg(char *arg);
void ii_action(int action_asn);
void ii_ack(void);
int ii_waitfd(void);
bool ii_ready(void);
int ii_getwidth(void);
char* ii_getheader(void);
char *fmt_ipinfo(ip_t *addr);
char *sep_ipinfo(ip_t *addr, char sep);
char *get_ipinfo(ip_t *addr, int nd);
void query_ipinfo(void);

#define ASLOOKUP_DEFAULT	NULL	// cymru
//#define ASLOOKUP_DEFAULT	"10,2"	// riswhois
#define IPINFO_MAX_ITEMS	25
extern int ipinfo_no[IPINFO_MAX_ITEMS];
extern int ipinfo_max;
extern bool enable_ipinfo;

#endif
