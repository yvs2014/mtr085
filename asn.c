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
#include <string.h>
#include <errno.h>
#include <search.h>
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
#include <sys/socket.h>

#include "mtr.h"
#include "version.h"
#include "asn.h"

/*
#ifndef IIDEBUG
#define IIDEBUG
#endif
*/

#ifdef IIDEBUG
#include <syslog.h>
#define IIDEBUG_MSG(x)	syslog x
#define IIDEBUG_ERR(x)	{ syslog x ; return NULL; }
#else
#define IIDEBUG_MSG(x)	
#define IIDEBUG_ERR(x)	
#endif

#define COMMA	','
#define VSLASH	'|'
#define SPACE	' '
//#define II_ITEM_MAX	14
#define II_ITEM_MAX	11
#define II_HTTP_RESP_LINES	20
#define NAMELEN	256
#define UNKN	"???"
#define RE_PORT	80

extern int af;                  /* address family of remote target */
extern int maxTTL;

int enable_ipinfo;

static int hash;
static int origin_no;
static int ipinfo_no[II_ITEM_MAX] = {-1};
static int ipinfo_max;
static char txtrec[NAMELEN];

typedef char* items_t[II_ITEM_MAX];
static items_t* items;

typedef char* http_resp_t[II_HTTP_RESP_LINES];

typedef struct {
    char* host;
    char* host6;
    char* unkn;
    char sep;
    int http_fd;
    int as_prfx_ndx;
    int fields;
    int width[II_ITEM_MAX];
} origin_t;
static origin_t origins[] = {
// ASN [ASN ..] | Route | CC | Registry | Allocated
    { "origin.asn.cymru.com", "origin6.asn.cymru.com", NULL, VSLASH, 0, 0, 5, { 6, 17, 4, 8, 11 } },
// ASN
    { "asn.routeviews.org", NULL, "4294967295", 0, 0, 0, 1, { 6 } },
//// ASN Network Network_Prefix
//    { "asn.routeviews.org", NULL, "4294967295", SPACE, 0, 0, 3, { 6, 15, 3 } },
// Route | "AS"ASN | Organization | Allocated | CC
    { "origin.asn.spameatingmonkey.net", NULL, "Unknown", VSLASH, 0, -1, 5, { 17, 8, 30, 11, 4 } },
// "AS"ASN
    { "ip2asn.sasm4.net", NULL, "No Record", 0, 0, -1, 1, { 8 } },
// Peers | ASN | Route | AS Name | CC | Website | Organization
    { "peer.asn.shadowserver.org", NULL, NULL, VSLASH, 0, 1, 7, { 36, 6, 17, 20, 4, 20, 30 } },
// IP, Country Code, Country, Region Code, Region, City, Zip, TimeZone, Lat, Long, Metro Code
    { "freegeoip.net", NULL, NULL, COMMA, -1, -1, 11, { 16, 4, 20, 4, 20, 20, 12, 20, 7, 7, 4 } },
//// Status, Country, Country Code, Region Code, Region, City, Zip, Lat, Long, TimeZone, ISP, Organization, ASN / AS Name, QueryIP
//    { "ip-api.com", NULL, NULL, COMMA, -1, -1, 17, { 7, 20, 4, 4, 20, 20, 12, 7, 7, 20, 20, 30, 7, 16 } },
};

char *get_dns_txt(const char *domain) {
    unsigned char answer[PACKETSZ],  *pt;
    char host[NAMELEN];
    char *txt;
    int len, exp, size, txtlen, type;

    if (res_init() < 0)
        IIDEBUG_ERR((LOG_INFO, "get_dns_txt(): res_init() failed: %s", strerror(errno)));

    memset(answer, 0, PACKETSZ);
    if ((len = res_query(domain, C_IN, T_TXT, answer, PACKETSZ)) < 0) {
        IIDEBUG_MSG((LOG_INFO, "get_dns_txt(): res_query() failed: %s", strerror(errno)));
        return (hash)?strdup(UNKN):UNKN;
	}

    pt = answer + sizeof(HEADER);

    if ((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0)
        IIDEBUG_ERR((LOG_INFO, "get_dns_txt(): dn_expand() failed: %s", strerror(errno)));

    pt += exp;

    GETSHORT(type, pt);
    if (type != T_TXT)
        IIDEBUG_ERR((LOG_INFO, "get_dns_txt(): Broken DNS reply"));

    pt += INT16SZ; /* class */

    if ((exp = dn_expand(answer, answer + len, pt, host, sizeof(host))) < 0)
        IIDEBUG_ERR((LOG_INFO, "get_dns_txt(): second dn_expand() failed: %s", strerror(errno)));

    pt += exp;
    GETSHORT(type, pt);
    if (type != T_TXT)
        IIDEBUG_ERR((LOG_INFO, "get_dns_txt(): Not a TXT record"));

    pt += INT16SZ; /* class */
    pt += INT32SZ; /* ttl */
    GETSHORT(size, pt);
    txtlen = *pt;

    if (txtlen >= size || !txtlen)
        IIDEBUG_ERR((LOG_INFO, "get_dns_txt(): Broken TXT record (txtlen = %d, size = %d)", txtlen, size));

    if (txtlen > NAMELEN)
        txtlen = NAMELEN;

    if (hash) {
        if (!(txt = malloc(txtlen + 1)))
            IIDEBUG_ERR((LOG_INFO, "get_dns_txt(): malloc() failed"));
    } else
        txt = (char*)txtrec;

    pt++;
    strncpy(txt, (char*) pt, txtlen);
    txt[txtlen] = 0;

    return txt;
}

int split_with_sep(char** args, int max, char sep) {
    if (!*args)
        return 0;

    int i = 0;
    char *p = *args, **a = args + 1;
    if (sep)
        for (; (p = strchr(p, sep)) && (i < max); i++) {
            *p++ = 0;
            if ((i + 1) < max)
                *a++ = p;
        }
    int j;
    for (j = 0; j < max; j++)
        if (args[j])
            args[j] = trim(args[j]);

    return (i + 1);
}

char* split_rec(char *rec, int ndx) {
    if (hash) {
        IIDEBUG_MSG((LOG_INFO, "Malloc-tbl: %s", rec));
        if (!(items = malloc(sizeof(*items)))) {
            free(rec);
            IIDEBUG_ERR((LOG_INFO, "split_rec(): malloc() failed"));
        }
    } else {
        IIDEBUG_MSG((LOG_INFO, "Not hashed: %s", rec));
        static items_t nothashed_items;
        items = &nothashed_items;
	}

    memset(items, 0, sizeof(*items));
    (*items)[0] = rec;
    int i = split_with_sep((char**)items, II_ITEM_MAX, origins[origin_no].sep);

    if (i > ipinfo_max)
        ipinfo_max = i;

    // special cases
    switch (origin_no) {
      case 0: // cymru.com: MultiAS
        if (origins[0].as_prfx_ndx < i) {
        char *p = (*items)[origins[0].as_prfx_ndx];
        if (p) {
            char *last = p + strlen(p) - 1;
            while ((p = strchr(p, ' ')))
                if (p != last)
                    *p = '/';
                else
                    break;
        }
      } break;
    }

    char *unkn = origins[origin_no].unkn;
    if (unkn) {
        int len = strlen(unkn);
        int j;
        for (j = 0; (j < i) && (*items)[j]; j++)
            if (!strncmp((*items)[j], unkn, len))
                (*items)[j] = UNKN;
    }

    return (ipinfo_no[ndx] < i) ? (*items)[ipinfo_no[ndx]] : (*items)[0];
}

char *get_http_csv(const char *request) {
    char buff[NAMELEN * II_HTTP_RESP_LINES];

    snprintf(buff, sizeof(buff), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mtr/%s\r\nAccept: */*\r\n\r\n", request, origins[origin_no].host, MTR_VERSION);
    if (send(origins[origin_no].http_fd, buff, strlen(buff), 0) < 0)
        IIDEBUG_ERR((LOG_INFO, "get_http_csv(): send() failed: %s", strerror(errno)));

	int sz;
	if ((sz = recv(origins[origin_no].http_fd, buff, sizeof(buff), 0)) <= 0)
        IIDEBUG_ERR((LOG_INFO, "get_http_csv(): recv() failed: %s", strerror(errno)));

	http_resp_t http_resp = {0};
	http_resp[0] = buff;
	int r = split_with_sep((char**)&http_resp, II_HTTP_RESP_LINES, '\n');
	if (strncmp(http_resp[0], "HTTP/1.1 200 OK", NAMELEN))
        IIDEBUG_ERR((LOG_INFO, "get_http_csv(): got \"%s\"", http_resp[0]));

	int content = 0, i;
	for (i=0; i < r; i++) {
		if (strncmp(http_resp[i], "", NAMELEN))	// skip header lines
			continue;
		if ((i + 1) < r)
			content = i + 1;
		break;
	}

    char *txt;
    if (hash) {
        if (!(txt = malloc(NAMELEN)))
            IIDEBUG_ERR((LOG_INFO, "get_http_csv(): malloc() failed"));
	} else
        txt = (char*)txtrec;
    snprintf(txt, NAMELEN, "%s", http_resp[content]);
    return txt;
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

    char hash_key[NAMELEN];
    char lookup_key[NAMELEN];

    if (af == AF_INET6) {
#ifdef ENABLE_IPV6
        if (!origins[origin_no].host6)
            return NULL;
        reverse_host6(addr, hash_key);
        sprintf(lookup_key, "%s.%s", hash_key, origins[origin_no].host6);
#else
        return NULL;
#endif
    } else {
        if (!origins[origin_no].host)
            return NULL;
        unsigned char buff[4];
        memcpy(buff, addr, 4);
        sprintf(hash_key, "%d.%d.%d.%d", buff[3], buff[2], buff[1], buff[0]);
        if (origins[origin_no].http_fd)
            sprintf(lookup_key, "/csv/%d.%d.%d.%d", buff[0], buff[1], buff[2], buff[3]);
        else
            sprintf(lookup_key, "%s.%s", hash_key, origins[origin_no].host);
    }

    char *val = NULL;
    ENTRY item;

    if (hash) {
        IIDEBUG_MSG((LOG_INFO, ">> Search for %s", hash_key));
        item.key = hash_key;
        ENTRY *found_item;
        if ((found_item = hsearch(item, FIND))) {
            if (!(val = (*((items_t*)found_item->data))[ipinfo_no[ndx]]))
                val = (*((items_t*)found_item->data))[0];
            IIDEBUG_MSG((LOG_INFO, "Found (hashed): %s", val));
        }
    }

    if (!val) {
        IIDEBUG_MSG((LOG_INFO, "Lookup for %s", hash_key));
        char *rec = origins[origin_no].http_fd ? get_http_csv(lookup_key) : get_dns_txt(lookup_key);
        if (rec) {
        if ((val = split_rec(rec, ndx))) {
            IIDEBUG_MSG((LOG_INFO, "Got %s", hash_key));
            if (hash)
                if ((item.key = strdup(hash_key))) {
                    item.data = (void*)items;
                    hsearch(item, ENTER);
#ifdef IIDEBUG
                    {
                        char buff[NAMELEN] = {0};
                        int i, len = 0;
                        for (i = 0; (i < II_ITEM_MAX) && (*items)[i]; i++) {
                            sprintf(buff + len, "\"%s\" ", (*items)[i]);
                            len = strlen(buff);
                        }
                        syslog(LOG_INFO, "Key %s: add %s", hash_key, buff);
                    }
#endif
                }
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
    char fmt[16];
    int len = 0;
    int i;
    for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++) {
        char *ipinfo = get_ipinfo(addr, i);
        int width = origins[origin_no].width[ipinfo_no[i]];
        if (ipinfo) {
            int l = strlen(ipinfo);
            if (!l)
                ipinfo = UNKN;
            if ((l >= width) && (width > 0))
                ipinfo[width - 1] = 0;
        } else
            ipinfo = UNKN;
        sprintf(fmt, "%s%%-%ds", (ipinfo_no[i] == origins[origin_no].as_prfx_ndx) ? "AS" : "", width);
        sprintf(fmtinfo + len, fmt, ipinfo);
        len = strlen(fmtinfo);
    }
    return fmtinfo;
}

void asn_open(void) {
    if (!hash) {
        IIDEBUG_MSG((LOG_INFO, "hcreate(%d)", maxTTL));
        if (!(hash = hcreate(maxTTL)))
            perror("hcreate()");
    }

    if (origins[origin_no].http_fd < 0) {	// ipv4 only by now
        IIDEBUG_MSG((LOG_INFO, "Make connection to %s", origins[origin_no].host));
        struct hostent* h;
        if ((h = gethostbyname(origins[origin_no].host)))
            perror(origins[origin_no].host);

        struct sockaddr_in re;
        re.sin_family = AF_INET;
        re.sin_port = htons(RE_PORT);
        re.sin_addr = *(struct in_addr*)h->h_addr;
        memset(&re.sin_zero, 0, sizeof(re.sin_zero));
        if ((origins[origin_no].http_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
            perror(origins[origin_no].host);

        int i;
        for (i = 0; h->h_addr_list[i]; i++) {
            re.sin_addr = *(struct in_addr*)h->h_addr_list[i];
            if (connect(origins[origin_no].http_fd, (struct sockaddr*) &re, sizeof(struct sockaddr)))
                return;
        }
        perror(origins[origin_no].host);
    }
}

void asn_close(void) {
    if (origins[origin_no].http_fd) {
        IIDEBUG_MSG((LOG_INFO, "Close connection to %s", origins[origin_no].host));
        close(origins[origin_no].http_fd);
	}

    if (hash) {
        IIDEBUG_MSG((LOG_INFO, "hdestroy()"));
        hdestroy();
        hash = enable_ipinfo = 0;
    }
}

void ii_parsearg(char *arg) {
    char* args[II_ITEM_MAX + 1];
    memset(args, 0, sizeof(args));
    if (arg) {
        args[0] = strdup(arg);
        split_with_sep((char**)&args, II_ITEM_MAX + 1, COMMA);
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

    if (args[0])
        free(args[0]);
    enable_ipinfo = 1;
    IIDEBUG_MSG((LOG_INFO, "ii origin: %s/%s", origins[origin_no].host, origins[origin_no].host6?origins[origin_no].host6:"-"));

    if (!hash)
        asn_open();
}

void ii_action(int action_asn) {
    if (ipinfo_no[0] >= 0) {
        if (action_asn)
            enable_ipinfo = !enable_ipinfo;
        else {
            int i;
            for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++) {
                ipinfo_no[i]++;
                if (!i)
                    enable_ipinfo = (ipinfo_no[0] < ipinfo_max) ? 1 : 0;
                if (ipinfo_no[i] >= ipinfo_max)
                    ipinfo_no[i] = 0;
            }
        }
    } else // init
        ii_parsearg(NULL);

    if (!hash)
        asn_open();
}

