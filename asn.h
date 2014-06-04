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

#ifndef ASN_H
#define ASN_H

// The autoconf system provides us with the NO_IPINFO define. 
// Littering the code with #ifndef NO_IPINFO (double negative)
// does not benefit readabilty. So here we invert the sense of the
// define. 
//
// Similarly, this include file should be included unconditially. 
// It will evaluate to nothing if we don't need it. 

#ifndef NO_IPINFO
#define IPINFO

extern int enable_ipinfo;
void asn_close();
char *fmt_ipinfo(ip_t *addr);
void ii_parsearg(char *arg);
void ii_action(int action_asn);
int ii_getwidth(void);

#endif
#endif
