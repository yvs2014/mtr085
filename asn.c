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
#include "net.h"
#include "asn.h"

//#define IIDEBUG
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
#define II_ITEM_MAX	11
#define II_HTTP_RESP_LINES	20
#define NAMELEN	256
#define UNKN	"???"
#define RE_PORT	80

extern struct __res_state _res;

extern int af;                  /* address family of remote target */
extern int maxTTL;

int enable_ipinfo;

static int htab_f;
static int origin_no;
static int ipinfo_no[II_ITEM_MAX] = {-1};
static int ipinfo_max;

typedef char* items_t[II_ITEM_MAX];
static items_t* items;

typedef struct {
    int status;
    char *key;
} ii_q_t;

typedef char* http_resp_t[II_HTTP_RESP_LINES];

typedef struct {
    char* host;
    char* host6;
    char* unkn;
    char sep;
    int type;	// 0 - dns, 1 - http
    int skip_first;
    int as_prfx_ndx;
    int fields;
    int width[II_ITEM_MAX];
    int fd;
} origin_t;
static origin_t origins[] = {
// ASN [ASN ..] | Route | CC | Registry | Allocated
    { "origin.asn.cymru.com", "origin6.asn.cymru.com", NULL, VSLASH, 0, 0, 0, 5, { 6, 17, 4, 8, 11 } },
//// ASN Network Network_Prefix
//    { "asn.routeviews.org", NULL, "4294967295", MULTITXT, 0, 0, 0, 3, { 6, 15, 3 } },
// ASN
    { "asn.routeviews.org", NULL, "4294967295", 0, 0, 0, 0, 1, { 6 } },
// Route | "AS"ASN | Organization | Allocated | CC
    { "origin.asn.spameatingmonkey.net", NULL, "Unknown", VSLASH, 0, 0, -1, 5, { 17, 8, 30, 11, 4 } },
// "AS"ASN
    { "ip2asn.sasm4.net", NULL, "No Record", 0, 0, 0, -1, 1, { 8 } },
// Peers | ASN | Route | AS Name | CC | Website | Organization
    { "peer.asn.shadowserver.org", NULL, NULL, VSLASH, 0, 0, 1, 7, { 36, 6, 17, 20, 4, 20, 30 } },
// IP, Country Code, Country, Region Code, Region, City, Zip, TimeZone, Lat, Long, Metro Code
    { "freegeoip.net", NULL, NULL, COMMA, 1, 1, -1, 11, { 16, 4, 20, 4, 20, 20, 12, 20, 8, 8, 4 } },
//// Status, Country, Country Code, Region Code, Region, City, Zip, Lat, Long, TimeZone, ISP, Organization, ASN / AS Name, QueryIP
//    { "ip-api.com", NULL, NULL, COMMA, 1, 0, -1, 17, { 7, 20, 4, 4, 20, 20, 12, 7, 7, 20, 20, 30, 7, 16 } },
};

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
    if (!(items = malloc(sizeof(*items)))) {
        free(rec);
        IIDEBUG_ERR((LOG_INFO, "split_rec(): malloc() failed"));
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

void add_rec(char *hkey) {
    ENTRY item = { hkey, items};
    hsearch(item, ENTER);
#ifdef IIDEBUG
    {
        char buff[NAMELEN] = {0};
        int i, len = 0;
        for (i = 0; (i < II_ITEM_MAX) && (*items)[i]; i++) {
            sprintf(buff + len, "\"%s\" ", (*items)[i]);
            len = strlen(buff);
        }
        IIDEBUG_MSG((LOG_INFO, "> Key %s: add %s", hkey, buff));
    }
#endif
}

ENTRY* search_hashed_id(word id) {
    word ids[2] = { id, 0 };
    ENTRY item;
    item.key = (void*)ids;
    ENTRY *hr;
    if (!(hr = hsearch(item, FIND)))
        IIDEBUG_ERR((LOG_INFO, "process_response(): unknown id=%d", id));
    IIDEBUG_MSG((LOG_INFO, "process_dns_response(): got id=%d", id));
    ((ii_q_t*)hr->data)->status = 1; // status: 1 (found)
    return hr;
}

void process_dns_response(char *buff, int r) {
    HEADER* header = (HEADER*)buff;
    ENTRY *hr;
    if (!(hr = search_hashed_id(header->id)))
        return;

    char host[NAMELEN], *pt;
    char *txt;
    int exp, size, txtlen, type;

    pt = buff + sizeof(HEADER);
    if ((exp = dn_expand(buff, buff + r, pt, host, sizeof(host))) < 0) {
        IIDEBUG_MSG((LOG_INFO, "process_dns_response(): dn_expand() failed: %s", strerror(errno)));
        return;
    }

    pt += exp;
    GETSHORT(type, pt);
    if (type != T_TXT) {
        IIDEBUG_MSG((LOG_INFO, "process_dns_response(): broken DNS reply"));
        return;
    }

    pt += INT16SZ; /* class */
    if ((exp = dn_expand(buff, buff + r, pt, host, sizeof(host))) < 0) {
        IIDEBUG_MSG((LOG_INFO, "process_dns_response(): second dn_expand() failed: %s", strerror(errno)));
        return;
    }

    pt += exp;
    GETSHORT(type, pt);
    if (type != T_TXT) {
        IIDEBUG_MSG((LOG_INFO, "process_dns_response(): not a TXT record"));
        return;
    }

    pt += INT16SZ; /* class */
    pt += INT32SZ; /* ttl */
    GETSHORT(size, pt);
    txtlen = *pt;
    if (txtlen >= size || !txtlen) {
        IIDEBUG_MSG((LOG_INFO, "process_dns_response(): broken TXT record (txtlen = %d, size = %d)", txtlen, size));
        return;
    }
    if (txtlen > NAMELEN)
        txtlen = NAMELEN;

    if (!(txt = malloc(txtlen + 1))) {
        IIDEBUG_MSG((LOG_INFO, "process_dns_response(): malloc() failed"));
        return;
    }

    pt++;
    strncpy(txt, (char*) pt, txtlen);
    txt[txtlen] = 0;

    if (!split_rec(txt, 0))
        return;
    add_rec(((ii_q_t*)hr->data)->key);
}

word str2hash(const char* s) {
    word h = 0;
    int c;
    while ((c = *s++))
        h = ((h << 5) + h) ^ c; // h * 33 ^ c
    return h;
}

void process_http_response(char *buff, int r) {
    http_resp_t http_resp = {0};
    http_resp[0] = buff;
    int rn = split_with_sep((char**)&http_resp, II_HTTP_RESP_LINES, '\n');
    if (strncmp(http_resp[0], "HTTP/1.1 200 OK", NAMELEN)) {
        IIDEBUG_MSG((LOG_INFO, "process_http_response(): got \"%s\"", http_resp[0]));
        return;
    }

    int content = 0, i;
    for (i=0; i < rn; i++) {
        if (strncmp(http_resp[i], "", NAMELEN))	// skip header lines
            continue;
        if ((i + 1) < rn)
            content = i + 1;
        break;
    }

    char *txt;
    int txtlen = strlen(http_resp[content]);
    if (!(txt = malloc(txtlen + 1))) {
        IIDEBUG_MSG((LOG_INFO, "process_http_response(): malloc() failed"));
        return;
    }
    strncpy(txt, http_resp[content], txtlen);
    txt[txtlen] = 0;

    IIDEBUG_MSG((LOG_INFO, "> http response: \"%s\"", txt));
    if (!split_rec(txt, 0))
        return;

    ENTRY *hr;
    if (!(hr = search_hashed_id(str2hash((*items)[0]))))
        return;

    add_rec(((ii_q_t*)hr->data)->key);
}

void ii_ack(void) {
    static unsigned char buff[PACKETSZ];
//    memset(buff, 0, PACKETSZ);
    int r;
    if ((r = recv(origins[origin_no].fd, buff, PACKETSZ, 0)) < 0) {
        IIDEBUG_MSG((LOG_INFO, "ii_ack(): recv() failed: %s", strerror(errno)));
        return; // return UNKN;
    }

    IIDEBUG_MSG((LOG_INFO, "> Got request"));
    switch (origins[origin_no].type) {
        case 1: // http
            process_http_response(buff, r);
            break;
        default: // dns
            process_dns_response(buff, r);
    }
}

int send_dns_query(const char *request, word id) {
    unsigned char buff[PACKETSZ];
    int r = res_mkquery(QUERY, request, C_IN, T_TXT, NULL, 0, NULL, buff, PACKETSZ);
    if (r < 0) {
        IIDEBUG_MSG((LOG_INFO, "send_dns_query(): res_mkquery() failed: %s", strerror(errno)));
        return r;
    }
    HEADER* h = (HEADER*)buff;
    h->id = id;
    return sendto(origins[origin_no].fd, buff, r, 0, (struct sockaddr *)&_res.nsaddr_list[0], sizeof(struct sockaddr));
}

int send_http_query(const char *request, word id) {
    unsigned char buff[PACKETSZ];
    snprintf(buff, sizeof(buff), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mtr/%s\r\nAccept: */*\r\n\r\n", request, origins[origin_no].host, MTR_VERSION);
    return send(origins[origin_no].fd, buff, strlen(buff), 0);
}

#ifdef ENABLE_IPV6
// from dns.c:addr2ip6arpa()
char *reverse_host6(struct in6_addr *addr, char *buff) {
    int i;
    char *b = buff;
    for (i=(sizeof(*addr)/2-1); i>=0; i--, b+=4) // 64b portion
        sprintf(b, "%x.%x.", addr->s6_addr[i] & 0xf, addr->s6_addr[i] >> 4);
    buff[strlen(buff) - 1] = 0;
    return buff;
}

char *frontward_host6(struct in6_addr *addr, char *buff) {
    int i;
    char *b = buff;
    for (i=0; i<=(sizeof(*addr)/2-1); i++, b+=4) // 64b portion
        sprintf(b, "%x.%x.", addr->s6_addr[i] >> 4, addr->s6_addr[i] & 0xf);
    buff[strlen(buff) - 1] = 0;
    return buff;
}
#endif

int ii_send_query(char *hkey, char *lookup_key) {
    word id[2] = { str2hash(hkey), 0 };
    ENTRY item = { (void*)id };
    ENTRY *hr;
    if ((hr=hsearch(item, FIND))) {
        IIDEBUG_MSG((LOG_INFO, "> Query(id=%d, key=%s) status: %d", *((word*)hr->key), ((ii_q_t*)hr->data)->key, ((ii_q_t*)hr->data)->status));
        return 0;
    }

    int r;
    IIDEBUG_MSG((LOG_INFO, "> Send %s query (id=%d)", lookup_key, id[0]));
    switch (origins[origin_no].type) {
        case 1: // http
            if ((r = send_http_query(lookup_key, id[0])) < 0)
                return r;
            break;
        default: // dns
            if ((r = send_dns_query(lookup_key, id[0])) < 0)
                return r;
    }
    if (!(item.key = malloc(sizeof(id))))
         return -1;
    memcpy(item.key, id, sizeof(id));
    if (!(item.data = malloc(sizeof(ii_q_t))))
         return -1;
    if (!(((ii_q_t*)item.data)->key = malloc(sizeof(hkey))))
         return -1;
    IIDEBUG_MSG((LOG_INFO, "> Add query(id=%d, key=%s) to the waitlist", id[0], hkey));
    ((ii_q_t*)item.data)->status = 0; // status: 0 (query for)
    ((ii_q_t*)item.data)->key = strdup(hkey);
    hsearch(item, ENTER);
    return 1;
}

char *get_ipinfo(ip_t *addr, int ndx) {
    if (!addr)
        return NULL;
    static char hkey[NAMELEN];
    static char lookup_key[NAMELEN];

    if (af == AF_INET6) {
#ifdef ENABLE_IPV6
        if (!origins[origin_no].host6)
            return NULL;
        sprintf(lookup_key, "%s.%s", reverse_host6(addr, hkey), origins[origin_no].host6);
        frontward_host6(addr, hkey);
#else
        return NULL;
#endif
    } else {
        if (!origins[origin_no].host)
            return NULL;
        unsigned char buff[4];
        memcpy(buff, addr, 4);
        sprintf(hkey, "%d.%d.%d.%d", buff[0], buff[1], buff[2], buff[3]);
        switch (origins[origin_no].type) {
            case 1: // http
                sprintf(lookup_key, "/csv/%d.%d.%d.%d", buff[0], buff[1], buff[2], buff[3]);
                break;
            default: // dns
                sprintf(lookup_key, "%d.%d.%d.%d.%s", buff[3], buff[2], buff[1], buff[0], origins[origin_no].host);
        }
    }

    char *val = NULL;
    ENTRY item;

//IIDEBUG_MSG((LOG_INFO, "> Search for %s", hkey));
    item.key = hkey;
    ENTRY *hashed;
    if ((hashed = hsearch(item, FIND))) {
        int i = ipinfo_no[ndx];
        if (origins[origin_no].skip_first)
            i++;
        if (!(val = (*((items_t*)hashed->data))[i]))
            val = (*((items_t*)hashed->data))[0];
//IIDEBUG_MSG((LOG_INFO, "> Found (hashed): %s", val));
    }
    if (!val)
        ii_send_query(hkey, lookup_key);
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
        char *ipinfo = addrcmp((void*)addr, (void*)&unspec_addr, af) ? get_ipinfo(addr, i) : NULL;
        int n = ipinfo_no[i];
        if (origins[origin_no].skip_first)
            n++;
        int width = origins[origin_no].width[n];
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

int ii_waitfd(void) {
    return origins[origin_no].fd;
}

void ii_open(void) {
    if (!htab_f) {
        IIDEBUG_MSG((LOG_INFO, "hcreate(%d * 2)", maxTTL));
        if (!(htab_f = hcreate(maxTTL * 2))) {
            perror("ii_open(): hcreate()");
            exit(-1);
        }
    }

    switch (origins[origin_no].type) {
        case 1:	// http (ipv4 only by now)
            IIDEBUG_MSG((LOG_INFO, "Make connection to %s", origins[origin_no].host));
            struct hostent* h;
            if (!(h = gethostbyname(origins[origin_no].host))) {
                perror(origins[origin_no].host);
                exit(-1);
            }

            struct sockaddr_in re;
            re.sin_family = AF_INET;
            re.sin_port = htons(RE_PORT);
            re.sin_addr = *(struct in_addr*)h->h_addr;
            memset(&re.sin_zero, 0, sizeof(re.sin_zero));
            if ((origins[origin_no].fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                perror(origins[origin_no].host);

            int i;
            for (i = 0; h->h_addr_list[i]; i++) {
                re.sin_addr = *(struct in_addr*)h->h_addr_list[i];
                if (connect(origins[origin_no].fd, (struct sockaddr*) &re, sizeof(struct sockaddr)))
                    return;
            }
            perror(origins[origin_no].host);
            exit(-1);
	default: // dns
            if (res_init() < 0) {
                IIDEBUG_MSG((LOG_INFO, "ii_open(): res_init() failed: %s", strerror(errno)));
                return;
            }
            if ((origins[origin_no].fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
                perror(origins[origin_no].host);
    }
}

void ii_close(void) {
    if (origins[origin_no].fd) {
        IIDEBUG_MSG((LOG_INFO, "Close connection to %s", origins[origin_no].host));
        close(origins[origin_no].fd);
    }
    if (htab_f) {
        IIDEBUG_MSG((LOG_INFO, "hdestroy()"));
        hdestroy();
        htab_f = enable_ipinfo = 0;
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
            int fn = origins[origin_no].fields;
            if (origins[origin_no].skip_first)
                fn--;
            int no = atoi(args[i]);
            if ((no > 0) && (no <= fn))
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

    if (!htab_f)
        ii_open();
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

    if (!htab_f)
        ii_open();
}

void query_iiaddr(ip_t *addr) {
  int i;
  for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++)
    get_ipinfo(addr, i);
}

void query_ipinfo(void) {
  int at, max = net_max();
  for (at = net_min(); at < max; at++) {
    ip_t *addr = net_addr(at);
    if (addrcmp((void *)addr, (void *)&unspec_addr, af) != 0) {
      query_iiaddr(addr);
      int i;
      for (i=0; i < MAXPATH; i++) {
        ip_t *addrs = net_addrs(at, i);
        if (addrcmp((void *)addrs, (void *)&unspec_addr, af) != 0)
          query_iiaddr(addrs);
      }
    }
  }
}

