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

#ifndef REPORT_H
#define REPORT_H

#include <stdbool.h>

void report_started_at(void);
void report_close(bool next, bool with_header);
#ifdef ENABLE_DNS
void report_resolv(void);
#endif
#ifdef OUTPUT_FORMAT_RAW
void raw_rawping(int at, int usec);
void raw_rawhost(int at, t_ipaddr *ipaddr);
#endif
#ifdef OUTPUT_FORMAT_CSV
void csv_close(bool next);
#endif
#ifdef OUTPUT_FORMAT_XML
void xml_close(void);
void xml_head(void);
void xml_tail(void);
#endif
#ifdef OUTPUT_FORMAT_JSON
void json_close(bool next);
void json_head(void);
void json_tail(void);
#endif

#endif
