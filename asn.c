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

#include "config.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#ifdef __APPLE__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <sys/socket.h>
#include <search.h>

#include "mtr.h"
#include "asn.h"

/*
#ifndef IIDEBUG
#define IIDEBUG
#include <syslog.h>
#endif
*/

#define II_ARGS_SEP	','
#define II_ITEM_SEP	'|'
#define II_ITEM_MAX	5
#define NAMELEN	128
#define UNKN	"???"

extern int af;                  /* address family of remote target */
extern int maxTTL;

int enable_ipinfo;

static int hash;
static int origin_no;
static int ipinfo_no[II_ITEM_MAX] = {-1};
static int ipinfo_max;

typedef char* items_t[II_ITEM_MAX];
static items_t* items;

typedef struct {
    char* ip4zone;
    char* ip6zone;
    int as_prfx_ndx;
    int fields;
    int width[II_ITEM_MAX];
} origin_t;
static origin_t origins[] = {
// ASN [ASN ..] | Route | CC | Registry | Allocated
    { "origin.asn.cymru.com", "origin6.asn.cymru.com", 0, 5, { 6, 17, 4, 8, 11 } },
// ASN
    { "asn.routeviews.org", NULL, 0, 1, { 6 } },
// Route | "AS"ASN | Organization | Allocated | CC
    { "origin.asn.spameatingmonkey.net", NULL, -1, 5, { 17, 8, 17, 11, 4 } },
};

char *ipinfo_lookup(const char *domain) {
    unsigned char answer[PACKETSZ],  *pt;
    char host[128];
    char *txt;
    int len, exp, size, txtlen, type;
    static char txtrec[NAMELEN];

    if(res_init() < 0) {
        fprintf(stderr,"@res_init failed\n");
        return NULL;
    }

    memset(answer, 0, PACKETSZ);
    if((len = res_query(domain, C_IN, T_TXT, answer, PACKETSZ)) < 0) {
#ifdef IIDEBUG
        if (hash)
            syslog(LOG_INFO, "Malloc-txt: %s", UNKN);
#endif
        return (hash)?strdup(UNKN):UNKN;
    }

    pt = answer + sizeof(HEADER);

    if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
        printf("@dn_expand failed\n"); return NULL;
    }

    pt += exp;

    GETSHORT(type, pt);
    if(type != T_TXT) {
        printf("@Broken DNS reply.\n"); return NULL;
    }

    pt += INT16SZ; /* class */

    if((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0) {
        printf("@second dn_expand failed\n"); return NULL;
    }

    pt += exp;
    GETSHORT(type, pt);
    if(type != T_TXT) {
        printf("@Not a TXT record\n"); return NULL;
    }

    pt += INT16SZ; /* class */
    pt += INT32SZ; /* ttl */
    GETSHORT(size, pt);
    txtlen = *pt;


    if(txtlen >= size || !txtlen) {
        printf("@Broken TXT record (txtlen = %d, size = %d)\n", txtlen, size); return NULL;
    }

    if (txtlen > NAMELEN)
        txtlen = NAMELEN;

    if (hash) {
        if (!(txt = malloc(txtlen + 1)))
            return NULL;
    } else
        txt = (char*)txtrec;

    pt++;
    strncpy(txt, (char*) pt, txtlen);
    txt[txtlen] = 0;

#ifdef IIDEBUG
    if (hash)
        syslog(LOG_INFO, "Malloc-txt(%p): %s", txt, txt);
#endif

    return txt;
}

int split_with_sep(char** args, int max, char sep) {
    if (!args)
        return -1;

    int i;
    char *p = *args, **a = args + 1;
    for (i = 0; (p = strchr(p, sep)) && (i < max); i++, *a++ = p)
        *p++ = 0;
    int j;
    for (j = 0; j < max; j++)
        if (args[j])
            args[j] = trim(args[j]);

    return (i + 1);
}

char* split_rec(char *rec, int ndx) {
    if (!rec)
	return NULL;
    if (hash) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "Malloc-tbl: %s", rec);
#endif
        if (!(items = malloc(sizeof(*items)))) {
#ifdef IIDEBUG
            syslog(LOG_INFO, "Free-txt(%p)", rec);
#endif
            free(rec);
            return NULL;
        }
    } else {
#ifdef IIDEBUG
        syslog(LOG_INFO, "Not hashed: %s", rec);
#endif
        static items_t nothashed_items;
        items = &nothashed_items;
	}

    memset(items, 0, sizeof(*items));
    (*items)[0] = rec;
    int i = split_with_sep((char**)items, II_ITEM_MAX, II_ITEM_SEP);

    if (i > ipinfo_max)
        ipinfo_max = i;

    // special cases
    switch (origin_no) {
      case 0: {	// cymru.com: MultiAS
        char *p = (*items)[origins[0].as_prfx_ndx];
        if (p) {
            char *last = p + strnlen(p, NAMELEN) - 1;
            while ((p = strchr(p, ' ')))
                if (p != last)
                    *p = '/';
                else
                    break;
        }
      } break;
      case 1: {	// originviews.org: unknown AS
#define S_UINT32_MAX "4294967295"
        int j;
        for (j = 0; (j < II_ITEM_MAX) && (*items)[j]; j++)
            if (!strncmp((*items)[j], S_UINT32_MAX, sizeof(S_UINT32_MAX)))
                (*items)[j] = UNKN;
      } break;
      case 2: {	// spameatingmonkey.net: unknown info
#define Unknown "Unknown"
        int j;
        for (j = 0; (j < II_ITEM_MAX) && (*items)[j]; j++)
            if (!strncmp((*items)[j], Unknown, sizeof(Unknown)))
                (*items)[j] = UNKN;
      } break;
    }

    if (ipinfo_no[ndx] >= i) {
        if (ipinfo_no[ndx] >= ipinfo_max)
            ipinfo_no[ndx] = 0;
        return (*items)[0];
    } else
        return (*items)[ipinfo_no[ndx]];
}

#ifdef ENABLE_IPV6
// from dns.c:addr2ip6arpa()
void reverse_host6(struct in6_addr *addr, char *buff) {
    int i;
    char *b = buff;
    for (i=(sizeof(*addr)/2-1); i>=0; i--, b+=4) // 64b portion
        sprintf(b, "%x.%x.", addr->s6_addr[i] & 0xf, addr->s6_addr[i] >> 4);
    buff[strlen(buff) - 1] = 0;
}
#endif

char *get_ipinfo(ip_t *addr, int ndx) {
    if (!addr)
        return NULL;

    char key[NAMELEN];
    char lookup_key[NAMELEN];

    if (af == AF_INET6) {
#ifdef ENABLE_IPV6
        if (!origins[origin_no].ip6zone)
            return NULL;
        reverse_host6(addr, key);
        if (snprintf(lookup_key, NAMELEN, "%s.%s", key, origins[origin_no].ip6zone) >= NAMELEN)
            return NULL;
#else
	return NULL;
#endif
    } else {
        if (!origins[origin_no].ip4zone)
            return NULL;
        unsigned char buff[4];
        memcpy(buff, addr, 4);
        if (snprintf(key, NAMELEN, "%d.%d.%d.%d", buff[3], buff[2], buff[1], buff[0]) >= NAMELEN)
            return NULL;
        if (snprintf(lookup_key, NAMELEN, "%s.%s", key, origins[origin_no].ip4zone) >= NAMELEN)
            return NULL;
    }

    char *val = NULL;
    ENTRY item;

    if (hash) {
#ifdef IIDEBUG
        syslog(LOG_INFO, ">> Search: %s", key);
#endif
        item.key = key;
        ENTRY *found_item;
        if ((found_item = hsearch(item, FIND))) {
            if (!(val = (*((items_t*)found_item->data))[ipinfo_no[ndx]]))
                val = (*((items_t*)found_item->data))[0];
#ifdef IIDEBUG
        syslog(LOG_INFO, "Found (hashed): %s", val);
#endif
        }
    }

    if (!val) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "Lookup: %s", key);
#endif
        if ((val = split_rec(ipinfo_lookup(lookup_key), ndx))) {
#ifdef IIDEBUG
            syslog(LOG_INFO, "Looked up: %s", key);
#endif
            if (hash)
                if ((item.key = strdup(key))) {
                    item.data = items;
                    hsearch(item, ENTER);
#ifdef IIDEBUG
                    {
                        char buff[NAMELEN] = {0};
                        int i, len = 0;
                        for (i = 0; (i < II_ITEM_MAX) && (*items)[i]; i++) {
                            snprintf(buff + len, sizeof(buff) - len, "\"%s\" ", (*items)[i]);
                            len = strnlen(buff, sizeof(buff));
                        }
                        syslog(LOG_INFO, "Insert into hash: \"%s\" => %s", key, buff);
                    }
#endif
                }
        }
    }

    return val;
}

int ii_getwidth(void) {
    int i, l = 0;
    for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++) {
        l += origins[origin_no].width[ipinfo_no[i]];
        if (ipinfo_no[i] == origins[origin_no].as_prfx_ndx)
            l += 2; // AS prfx
    }
    return l;
}

char *fmt_ipinfo(ip_t *addr) {
    static char fmtinfo[NAMELEN];
    int len = 0;
    int i;
    for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++) {
        char *ipinfo = get_ipinfo(addr, i);
        char fmt[8];
        int width = origins[origin_no].width[ipinfo_no[i]];
        if (ipinfo_no[i] != ipinfo_max) {
          if (ipinfo) {
            int l = strnlen(ipinfo, NAMELEN);
            if (!l)
              ipinfo = UNKN;
            if (l >= width)
              width = strnlen(ipinfo, NAMELEN) + 1;	// +1 for space
          } else
            ipinfo = UNKN;
          snprintf(fmt, sizeof(fmt), "%s%%-%ds",
              (ipinfo_no[i] == origins[origin_no].as_prfx_ndx) ? "AS" : "", width);
          snprintf(fmtinfo + len, sizeof(fmtinfo) - len, fmt, ipinfo);
          len = strnlen(fmtinfo, sizeof(fmtinfo));
        } else {	// empty item
          snprintf(fmt, sizeof(fmt), "  %%-%ds", width);
          snprintf(fmtinfo + len, sizeof(fmtinfo) - len, fmt, "");
          len = strnlen(fmtinfo, sizeof(fmtinfo));
        }
    }
    return fmtinfo;
}

void asn_open(void) {
    if (!hash) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "hcreate(%d)", maxTTL);
#endif
        if (!(hash = hcreate(maxTTL)))
            perror("ipinfo hash");
    }
}

void asn_close(void) {
    if (hash) {
#ifdef IIDEBUG
        syslog(LOG_INFO, "hdestroy()");
#endif
        hdestroy();
        hash = enable_ipinfo = 0;
    }
}

void ii_parsearg(char *arg) {
    if (!hash)
        asn_open();

    char* args[II_ITEM_MAX + 1];
    memset(args, 0, sizeof(args));
    args[0] = strdup(arg);
    split_with_sep((char**)&args, II_ITEM_MAX + 1, II_ARGS_SEP);

    if (args[0]) {
        int no = atoi(args[0]);
        if ((no > 0) && (no <= (sizeof(origins)/sizeof(origins[0]))))
            origin_no = no - 1;
    }

    int i, j;
    for (i = 1, j = 0; (j < II_ITEM_MAX) && (i <= II_ITEM_MAX); i++)
		if (args[i]) {
    	    int no = atoi(args[i]);
       	    if ((no > 0) && (no <= origins[origin_no].fields))
       	        ipinfo_no[j++] = no - 1;
    	}
    for (i = j; i < II_ITEM_MAX; i++)
        ipinfo_no[i] = -1;
    if (ipinfo_no[0] < 0)
        ipinfo_no[0] = 0;

    free(args[0]);
    enable_ipinfo = 1;
#ifdef IIDEBUG
    syslog(LOG_INFO, "ii origin: \"%s\" \"%s\"", origins[origin_no].ip4zone, origins[origin_no].ip6zone);
#endif
}

void ii_action(int action_asn) {
   if (!hash)
       asn_open();

   if (ipinfo_no[0] >= 0) {
       int i;
       for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++) {
           ipinfo_no[i]++;
           if (ipinfo_no[i] > ipinfo_max)
               ipinfo_no[i] = 0;
       }
       enable_ipinfo = (ipinfo_no[0] != ipinfo_max) ? 1 : 0;
   } else	// init
       ii_parsearg(action_asn ? "2" : "");
       // action asn:	origin 2:	asn.routeviews.org
       // action ipinfo:	default origin:	origin.asn.cymru.com
}

