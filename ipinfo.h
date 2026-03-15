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
#include <sys/types.h>

bool  ipinfo_init(const char *arg);
void  ipinfo_close(void);
bool  ipinfo_action(int action); // open() if necessary
void  ipinfo_parse(int sock, int seq);
bool  ipinfo_ready(void);
int   ipinfo_width(void);
bool  ipinfo_timedout(int seq);
void  ipinfo_seq_ready(int seq);

const char* ipinfo_head_fix(void);
const char* ipinfo_head_div(char div);
const char* ipinfo_data_fix(int at, int ndx);
const char* ipinfo_data_div(int at, int ndx, char div);

void query_ipinfo(void);

#define ASLOOKUP_DEFAULT   "2,2" // ripe whois
extern bool ipinfo_tcpmode;
extern uint ipinfo_queries[];
extern uint ipinfo_replies[];

#endif
