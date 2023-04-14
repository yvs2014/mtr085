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

#include "config.h"

void report_open(void);
void report_close(bool wide);
#ifdef OUTPUT_FORMAT_RAW
extern bool enable_raw;
void raw_rawping(int at, int usec);
void raw_rawhost(int at, ip_t *addr);
#endif
#ifdef OUTPUT_FORMAT_TXT
void txt_close(bool notfirst);
#endif
#ifdef OUTPUT_FORMAT_CSV
void csv_close(bool notfirst);
#endif
#ifdef OUTPUT_FORMAT_XML
void xml_close(void);
void xml_head(void);
void xml_tail(void);
#endif
#ifdef OUTPUT_FORMAT_JSON
void json_close(bool notfirst);
void json_head(void);
void json_tail(void);
#endif

#endif
