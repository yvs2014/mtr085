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

void  ipinfo_open(void);
void  ipinfo_close(void);
int   ipinfo_args(char *arg);
void  ipinfo_action(int action);
void  ipinfo_parse(void);
int   ipinfo_wait(void);
bool  ipinfo_ready(void);
int   ipinfo_width(void);
char* ipinfo_header(void);

char  *fmt_ipinfo(int at, int ndx);
char  *sep_ipinfo(int at, int ndx, char sep);
void query_ipinfo(void);

#define ASLOOKUP_DEFAULT	NULL	// cymru
//#define ASLOOKUP_DEFAULT	"2,2"	// riswhois
extern bool enable_ipinfo;
extern unsigned ipinfo_queries[];
extern unsigned ipinfo_replies[];

#endif
