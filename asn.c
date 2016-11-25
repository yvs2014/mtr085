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
#include <ctype.h>

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
#include "dns.h"
#include "display.h"
#include "asn.h"

//#define IIDEBUG
#ifdef IIDEBUG
#include <syslog.h>
#define IIDEBUG_MSG(x)	syslog x
#define IIDEBUG_ERR(x)	{ syslog x ; return NULL; }
#else
#define IIDEBUG_MSG(x)	
#define IIDEBUG_ERR(x)	{ return NULL; }
#endif

#define COMMA	','
#define VSLASH	'|'
#define II_ITEM_MAX	25
#define II_HTTP_RESP_LINES	100
#define NAMELEN	256
#define UNKN	"?"
#define REMOTE_PORT	80

#define RECV_BUFF_SZ	3000

extern struct __res_state _res;

extern int af;                  /* address family of remote target */
extern int maxTTL;
extern char mtr_args[];

int enable_ipinfo;

static int init;
static int origin_no;
static int ipinfo_no[II_ITEM_MAX] = {-1};
static int ipinfo_max;
static int skipped_items;

typedef char* items_t[II_ITEM_MAX];
static items_t* items;

typedef struct {
    int status;
    char *key;
} ii_q_t;

#define TMPFILE	"/tmp/mtr-map-XXXXXX"
char tmpfn[] = TMPFILE;
static int tmpfd;
typedef char* http_resp_t[II_HTTP_RESP_LINES];

typedef struct {
    char* host;
    char* host6;
    char* unkn;
    char sep;
    char* name[II_ITEM_MAX];
    char* name_prfx;
    int type;	// 0 - dns:csv, 1 - http:csv, 2 - http:flat-json
    int skip[II_ITEM_MAX]; // query ip, ...
    char* prefix;
    char* suffix;
    char* sub[2 * II_ITEM_MAX];
    int width[II_ITEM_MAX];
    int fd;
} origin_t;

static origin_t origins[] = {
// Abbreviations: CC - Country Code, RC - Region Code, MC - Metro Code, Org - Organization, TZ - TimeZone
    { "origin.asn.cymru.com", "origin6.asn.cymru.com", NULL, VSLASH,
        { "ASN", "Route", "CC", "Registry", "Allocated" } },

    { "asn.routeviews.org", NULL, "4294967295", 0,
        { "ASN" } },

    { "origin.asn.spameatingmonkey.net", NULL, "Unknown", VSLASH,
        { "Route", "ASN", "Org", "Allocated", "CC" } },

    { "ip2asn.sasm4.net", NULL, "No Record", 0,
        { "ASN" } },

    { "peer.asn.shadowserver.org", NULL, NULL, VSLASH,
        { "Peers", "ASN", "Route", "AS Name", "CC", "Website", "Org" } },

    { "freegeoip.net", NULL, NULL, COMMA,
        { /* QueryIP, */ "CC", "Country", "RC", "Region", "City", "Zip", "TZ", "Lat", "Long", "MC" },
        NULL, 1, {1}, "/csv/" },

    { "ip-api.com", NULL, NULL, COMMA,
        { /* Status, */ "Country", "CC", "RC", "Region", "City", "Zip", "Lat", "Long", "TZ", "ISP", "Org", "AS Name" /*, QueryIP */ },
        NULL, 1, {14, 1}, "/csv/" },

    { "getcitydetails.geobytes.com", NULL, NULL, COMMA,
        {}, // { /* ForwarderFor, RemoteIP, QueryIP,*/ "Certainty", "Internet", "Country", "RLC", "Region", "RC", "LC", "DMA", "City", "CityID", "FQCN", "Lat", "Long", "Capital", "TZ", "Nationality", "Population", "NatinalityPlural", "MapReference", "Currency", "CurrencyCode", "Title" },
        "geobytes", 2, {3, 1, 2}, "/GetCityDetails?fqcn=", NULL,
        { "code", "Code", "location", "Location", "cityid", "CityID", "dma", "DMA",
          "fqcn", "FQCN", "singular", "Singular", "plural", "Plural", "reference", "Reference"},
    },

    { "ipinfo.io", NULL, NULL, COMMA,
        {}, // { /* QueryIP, Hostname, */ "City", "Region", "CC", "Location", "AS Name", "Postal" },
        NULL, 2, {1, 2}, "/", "/json" },
};

int split_with_sep(char** args, int max, char sep, char quote) {
    if (!*args)
        return 0;

    int i, inside = 0;
    char *p, **a = args + 1;
    for (i = 0, p = *args; *p; p++)
        if ((*p == sep) && !inside) {
            i++;
            if (i >= max)
                break;
            *p = 0;
            *a++ = p + 1;
        } else
            if (*p == quote)
                inside = !inside;

    int j;
    for (j = 0; j < max; j++)
        if (args[j])
            args[j] = trim(args[j]);
    return (i < max) ? (i + 1) : max;
}

char* split_rec(char *rec) {
    if (!(items = malloc(sizeof(*items)))) {
        free(rec);
        IIDEBUG_ERR((LOG_INFO, "split_rec(): malloc() failed"));
    }

    memset(items, 0, sizeof(*items));
    (*items)[0] = rec;
    int i = split_with_sep(*items, II_ITEM_MAX, origins[origin_no].sep, '"');

    if (i > (ipinfo_max + skipped_items))
        ipinfo_max = i - skipped_items;

    char *unkn = origins[origin_no].unkn;
    if (unkn) {
        int len = strlen(unkn);
        int j;
        for (j = 0; (j < i) && (*items)[j]; j++)
            if (!strncmp((*items)[j], unkn, len))
                (*items)[j] = UNKN;
    }

    return (ipinfo_no[0] < i) ? (*items)[ipinfo_no[0]] : (*items)[0];
}

void add_rec(char *hkey) {
    if (origins[origin_no].skip[0]) {
        items_t it;
        memcpy(&it, items, sizeof(it));
        memset(items, 0, sizeof(items_t));
        int i, j;
        for (i = j = 0; i < II_ITEM_MAX; i++) {
            int k, skip = 0;
            for (k = 0; (k < II_ITEM_MAX) && origins[origin_no].skip[k]; k++)
                if ((skip = ((i + 1) == origins[origin_no].skip[k]) ? 1 : 0))
                    break;
            if (!skip)
                (*items)[j++] = it[i];
        }
    }

    ENTRY *hr, item = { hkey, items};
    if (!(hr = hsearch(item, ENTER))) {
        IIDEBUG_MSG((LOG_INFO, "hsearch(ENTER, key=%s) failed: %s", hkey, strerror(errno)));
        return;
    }

#ifdef IIDEBUG
    static char buff[II_ITEM_MAX * (NAMELEN + 1)];
    memset(buff, 0, sizeof(buff));
    int l = 0;
#endif
    int i;
    for (i = 0; (i < II_ITEM_MAX) && (*items)[i]; i++) {
        int ilen = strnlen((*items)[i], NAMELEN);
        if (origins[origin_no].width[i] < ilen)
            origins[origin_no].width[i] = ilen;
#ifdef IIDEBUG
        l += snprintf(buff + l, sizeof(buff) - l, "\"%s\" ", (*items)[i]);
#endif
    }
    IIDEBUG_MSG((LOG_INFO, "Key %s: add %s", hkey, buff));
}

ENTRY* search_hashed_id(word id) {
    word ids[2] = { id, 0 };
    ENTRY *hr, item = { (void*)ids };
    if (!(hr = hsearch(item, FIND)))
        IIDEBUG_ERR((LOG_INFO, "hsearch(FIND): key=%d not found", id));

    IIDEBUG_MSG((LOG_INFO, "process response id=%d", id));
    ((ii_q_t*)hr->data)->status = 1; // status: 1 (found)
    return hr;
}

word str2hash(const char* s) {
    word h = 0;
    int c;
    while ((c = *s++))
        h = ((h << 5) + h) ^ c; // h * 33 ^ c
    return h;
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

    if (!split_rec(txt))
        return;
IIDEBUG_MSG((LOG_INFO, "call add_rec00"));
    add_rec(((ii_q_t*)hr->data)->key);
IIDEBUG_MSG((LOG_INFO, "call add_rec01"));
}

char trim_c(char *s, char *sc) {
    char c;
    while ((c = *sc++)) if (*s == c) { *s = 0; break;}
    return (*s);
}

char* trim_str(char *s, char *sc) {
    char *p;
    int i, l = strlen(s);
    for (i = l - 1, p = s + l - 1; i >= 0; i--, p--)
        if (trim_c(p, sc)) break;
    for (i = 0, p = s, l = strlen(s); i < l; i++, p++)
        if (trim_c(p, sc)) break;
    return p;
}

void schng(char *str, char *from, char *to) {
    char *s;
    if ((s = strstr(str, from)))
        memcpy(s, to, strlen(to));
}

void split_pairs(char sep) {
    items_t it;
    memcpy(&it, items, sizeof(it));
    memset(items, 0, sizeof(*items));

    int i;
    for (i = 0; (i < II_ITEM_MAX) && it[i]; i++) {
        char* ln[2] = { it[i] };
//        (*items)[i] = (split_with_sep(ln, 2, sep, 0) == 2) ? trim(ln[1]) : it[i]; // skip names
/* don't skip names */
        if (split_with_sep(ln, 2, sep, 0) == 2) {
            int skip = 0, j;
            for (j = 0; (j < II_ITEM_MAX) && origins[origin_no].skip[j]; j++)
                if ((i + 1) == origins[origin_no].skip[j]) {
                   skip = 1;
                   break;
                }
            if (!skip) {
                int n = i - skipped_items;
                if (n >= 0) {
                    char *name = trim_str(ln[0], "\"'{}");
                    if (name) {
                        if (origins[origin_no].name_prfx)
                            if (strstr(name, origins[origin_no].name_prfx))
                                name += strlen(origins[origin_no].name_prfx);
                        if (origins[origin_no].sub[0])
                            for (j = 0; (j < (2 * II_ITEM_MAX - 1)) && origins[origin_no].sub[j]; j += 2)
                                schng(name, origins[origin_no].sub[j], origins[origin_no].sub[j + 1]);
                        if (name[0])
                            name[0] = toupper((int)name[0]);
                        origins[origin_no].name[n] = strdup(name);
                        int l = strlen(name);
                        if (origins[origin_no].width[n] < l)
                            origins[origin_no].width[n] = l;
                    }
                }
            }
            (*items)[i] = trim(ln[1]);
        } else
            (*items)[i] = it[i];
/**/
    }
}

void process_http_response(char *buff, int r) {
    static char h11[] = "HTTP/1.1";
    static int h11_ln = sizeof(h11) - 1;
    static char h11ok[] = "HTTP/1.1 200 OK";
    static int h11ok_ln = sizeof(h11ok) - 1;

    IIDEBUG_MSG((LOG_INFO, "Got[%d]: \"%s\"", r, buff));
#ifdef IIDEBUG
    int reply = 0;
#endif
    char *p;
    for (p = buff; (p = strstr(p, h11)); p += h11_ln) {	// parse pipelining chunks
#ifdef IIDEBUG
        reply++;
#endif
        if (!strncmp(p, h11ok, h11ok_ln)) {
            static http_resp_t http_resp;
            memset(http_resp, 0, sizeof(http_resp));
            static unsigned char copy[RECV_BUFF_SZ]; // chunk + '\0'
            memset(copy, 0, sizeof(copy));
            memcpy(copy, p, sizeof(copy));
            http_resp[0] = copy;

            int rn = split_with_sep(http_resp, II_HTTP_RESP_LINES, '\n', 0);
            if (rn < 4) { // HEADER + NL + NL + DATA
                IIDEBUG_MSG((LOG_INFO, "process_http_response(): empty response #%d", reply));
                continue;
            }

            int content = 0, cnt_len = 0, i;
            for (i = 0; i < rn; i++) {
                char* ln[2] = { http_resp[i] };
                if (split_with_sep(ln, 2, ' ', 0) == 2)
                    if (strcmp("Content-Length:", ln[0]) == 0)
                        cnt_len = atoi(ln[1]);
                if (http_resp[i][0])	// skip header lines
                    continue;
                if ((i + 1) < rn)
                    content = i + 1;
                break;
            }
            if (content && (cnt_len > 0) && (cnt_len < r))
                *(http_resp[content] + cnt_len) = 0;
            else
                cnt_len = strlen(http_resp[content]);

            char *txt;
            if (!(txt = malloc(cnt_len + 1))) {
                IIDEBUG_MSG((LOG_INFO, "process_http_response(): reply #%d: malloc() failed", reply));
                continue;
            }
            memset(txt, 0, cnt_len);
            for (i = content; (i < rn) && (strlen(txt) < cnt_len); i++) { // combine into one line
                if (((http_resp[i] - http_resp[content]) + strlen(http_resp[i])) > cnt_len)
                    break;
                strcat(txt, http_resp[i]);
            }

            IIDEBUG_MSG((LOG_INFO, "http response#%d [%d]: \"%s\"", reply, rn, txt));
            if (!split_rec(txt))
                continue;
            if (origins[origin_no].type == 2)
                split_pairs(':');

            { int j;
              for (j = 0; (j < II_ITEM_MAX) && (*items)[j]; j++) // disclose items
                (*items)[j] = trim_str((*items)[j], "\"'{}");
            }

            ENTRY *hr;
            // first entry of the skip-table is our request
            if (!(hr = search_hashed_id(str2hash((*items)[origins[origin_no].skip[0] - 1])))) {
                IIDEBUG_MSG((LOG_INFO, "process_http_response(): got unknown reply #%d: \"%s\"", reply, (*items)[origins[origin_no].skip[0] - 1]));
                continue;
            }
            add_rec(((ii_q_t*)hr->data)->key);
        } else {
            IIDEBUG_MSG((LOG_INFO, "process_http_response(): reply#%d is not OK: got \"%s\"", reply, p));
        }
    }

#ifdef IIDEBUG
    if (!reply)
        IIDEBUG_MSG((LOG_INFO, "process_http_response(): What is that? got[%d] \"%s\"", r, buff));
#endif
}

typedef void (*process_response_f)(char*, int);
static process_response_f process_response[] = { process_dns_response, process_http_response, process_http_response };

void ii_ack(void) {
    static unsigned char buff[RECV_BUFF_SZ];
    int r;
    if ((r = recv(origins[origin_no].fd, buff, RECV_BUFF_SZ, 0)) < 0) {
        IIDEBUG_MSG((LOG_INFO, "ii_ack(): recv() failed: %s", strerror(errno)));
        return; // return UNKN;
    }
    if (!r) { // Got 0 bytes
        IIDEBUG_MSG((LOG_INFO, "Close connection to %s", origins[origin_no].host));
        close(origins[origin_no].fd);
        origins[origin_no].fd = 0;
        return;
    }
    process_response[origins[origin_no].type](buff, r);
}

int init_dns(void) {
    IIDEBUG_MSG((LOG_INFO, "ipinfo: dns init"));
    if (res_init() < 0) {
        perror("res_init()");
        return -1;
    }
    if ((origins[origin_no].fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }
    return 0;
}

int open_http_connection(void) {
    IIDEBUG_MSG((LOG_INFO, "Open connection to %s", origins[origin_no].host));
    struct hostent* h;
    if (!(h = gethostbyname(origins[origin_no].host))) {
        perror(origins[origin_no].host);
        return -1;
    }

    struct sockaddr_in re;
    re.sin_family = AF_INET;
    re.sin_port = htons(REMOTE_PORT);
    re.sin_addr = *(struct in_addr*)h->h_addr;
    memset(&re.sin_zero, 0, sizeof(re.sin_zero));
    if ((origins[origin_no].fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }

    int i;
    for (i = 0; h->h_addr_list[i]; i++) {
        re.sin_addr = *(struct in_addr*)h->h_addr_list[i];
        if (connect(origins[origin_no].fd, (struct sockaddr*) &re, sizeof(struct sockaddr)) >= 0) {
            init = 1;
            return 0;
        }
    }
    perror("connect()");
    close(origins[origin_no].fd);
    origins[origin_no].fd = 0;
    return -1;
}

typedef int (*open_connection_f)(void);
static open_connection_f open_connection[] = { init_dns, open_http_connection, open_http_connection };

int send_dns_query(const char *request, word id) {
    unsigned char buff[RECV_BUFF_SZ];
    int r = res_mkquery(QUERY, request, C_IN, T_TXT, NULL, 0, NULL, buff, RECV_BUFF_SZ);
    if (r < 0) {
        IIDEBUG_MSG((LOG_INFO, "send_dns_query(): res_mkquery() failed: %s", strerror(errno)));
        return r;
    }
    HEADER* h = (HEADER*)buff;
    h->id = id;
    return sendto(origins[origin_no].fd, buff, r, 0, (struct sockaddr *)&_res.nsaddr_list[0], sizeof(struct sockaddr));
}

int send_http_query(const char *request, word id) {
    unsigned char buff[RECV_BUFF_SZ];
    snprintf(buff, sizeof(buff), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mtr/%s\r\nAccept: */*\r\n\r\n", request, origins[origin_no].host, MTR_VERSION);
    return send(origins[origin_no].fd, buff, strlen(buff), 0);
}

typedef int (*send_query_f)(const char*, word);
static send_query_f send_query[] = { send_dns_query, send_http_query, send_http_query };

int ii_send_query(char *hkey, char *lookup_key) {
    word id[2] = { str2hash(hkey), 0 };
    ENTRY item = { (void*)id };
    if (hsearch(item, FIND)) {
        IIDEBUG_MSG((LOG_INFO, "Query %s (id=%d) on the waitlist", lookup_key, id[0]));
        return 0;
    }

    int r;
    if (!origins[origin_no].fd)
        if ((r = open_connection[origins[origin_no].type]()) < 0)
            return r;

    IIDEBUG_MSG((LOG_INFO, "Send %s query (id=%d)", lookup_key, id[0]));
    if ((r = send_query[origins[origin_no].type](lookup_key, id[0])) <= 0)
        return r;

    if (!(item.key = malloc(sizeof(id))))
        return -1;
    memcpy(item.key, id, sizeof(id));
    if (!(item.data = malloc(sizeof(ii_q_t))))
        return -1;
    if (!(((ii_q_t*)item.data)->key = malloc(sizeof(hkey))))
        return -1;
    ((ii_q_t*)item.data)->status = 0; // status: 0 (query for)
    ((ii_q_t*)item.data)->key = strdup(hkey);

    IIDEBUG_MSG((LOG_INFO, "Add query(key=%d, data=%s) to the waitlist", id[0], hkey));
    if (!hsearch(item, ENTER)) {
        IIDEBUG_MSG((LOG_INFO, "hsearch(ENTER, key=%d, data=%s) failed: %s", id[0], hkey, strerror(errno)));
        return -1;
    }

    return 0;
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

char *get_ipinfo(ip_t *addr, int nd) {
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
            case 2: // http:flat-json
            case 1: // http:csv
                sprintf(lookup_key, "%s%s", origins[origin_no].prefix, hkey);
                if (origins[origin_no].suffix)
                    sprintf(lookup_key + strlen(lookup_key), "%s", origins[origin_no].suffix);
                break;
            default: // dns
                sprintf(lookup_key, "%d.%d.%d.%d.%s", buff[3], buff[2], buff[1], buff[0], origins[origin_no].host);
        }
    }

    ENTRY *hr, item = { hkey };
    if ((hr = hsearch(item, FIND)))
        return (*((items_t*)hr->data))[nd];
    else
        ii_send_query(hkey, lookup_key);
    return NULL;
}

#define FIELD_FMT	"%%-%ds "
char* ii_getheader(void) {
    static char header[NAMELEN];
    char fmt[16];
    int i, l = 0;
    for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < ipinfo_max) && (l < NAMELEN) && origins[origin_no].name[ipinfo_no[i]]; i++) {
        snprintf(fmt, sizeof(fmt), FIELD_FMT, origins[origin_no].width[ipinfo_no[i]]);
        l += snprintf(header + l, sizeof(header) - l, fmt, origins[origin_no].name[ipinfo_no[i]]);
    }
    return l ? header : NULL;
}

int ii_getwidth(void) {
    int i, l = 0;
    for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < ipinfo_max); i++)
        l += origins[origin_no].width[ipinfo_no[i]] + 1;
    return l;
}

char *fmt_ipinfo(ip_t *addr) {
    static char fmtinfo[NAMELEN];
    char fmt[16];
    int l = 0, i;
    for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++) {
        char *ipinfo = addrcmp((void*)addr, (void*)&unspec_addr, af) ? get_ipinfo(addr, ipinfo_no[i]) : NULL;
        int width = origins[origin_no].width[ipinfo_no[i]];
        if (!width)
            continue;
        if (!ipinfo) {
            if (ipinfo_no[i] >= ipinfo_max)
                continue;
            ipinfo = UNKN;
        }
        snprintf(fmt, sizeof(fmt), FIELD_FMT, width);
        l += snprintf(fmtinfo + l, sizeof(fmtinfo) - l, fmt, ipinfo);
    }
    return fmtinfo;
}

int ii_waitfd(void) {
    return (enable_ipinfo && init) ? origins[origin_no].fd : 0;
}

int ii_ready(void) {
    return (enable_ipinfo && init) ? 1 : 0;
}

void ii_open(void) {
   if (init)
       return;
   if (!hcreate(maxTTL * 2)) {
       perror("hcreate()");
       return;
   }
   if (open_connection[origins[origin_no].type]() < 0)
       return;
   while ((skipped_items < II_ITEM_MAX) && origins[origin_no].skip[skipped_items])
       skipped_items++;

   int i;
   for (i = 0; i < II_ITEM_MAX; i++) {
       if (!origins[origin_no].name[i])
           break;
       origins[origin_no].width[i] = strnlen(origins[origin_no].name[i], NAMELEN);
   }

   init = 1;
}

void ii_close(void) {
    if (origins[origin_no].fd)
        close(origins[origin_no].fd);
    hdestroy();
    enable_ipinfo = 0;
    if (tmpfd) {
        close(tmpfd);
#ifndef IIDEBUG
        unlink(tmpfn);
#endif
    }
}

void ii_parsearg(char *arg) {
    char* args[II_ITEM_MAX + 1];
    memset(args, 0, sizeof(args));
    if (arg) {
        args[0] = strdup(arg);
        split_with_sep(args, II_ITEM_MAX + 1, COMMA, 0);
        int no = atoi(args[0]);
        if ((no > 0) && (no <= (sizeof(origins)/sizeof(origins[0]))))
            origin_no = no - 1;
    }

    int i, j;
    for (i = 1, j = 0; (j < II_ITEM_MAX) && (i <= II_ITEM_MAX); i++)
        if (args[i]) {
            int no = atoi(args[i]);
            if (no > 0)
                ipinfo_no[j++] = no - 1;
        }
    for (i = j; i < II_ITEM_MAX; i++)
        ipinfo_no[i] = -1;
    if (ipinfo_no[0] < 0)
        ipinfo_no[0] = 0;

    if (args[0])
        free(args[0]);
    enable_ipinfo = 1;
    IIDEBUG_MSG((LOG_INFO, "Data source: %s/%s", origins[origin_no].host, origins[origin_no].host6?origins[origin_no].host6:"-"));

    if (!init)
        ii_open();
}

char hbody_begin[] = "<body>\
    <script src=\"http://maps.googleapis.com/maps/api/js?libraries=geometry&sensor=false\"></script>\
    <script>\
        var hopes = [\
";
char hbody_end[] = "];\
        function Label(opt_options) {\
            this.setValues(opt_options);\
            var span = this.span_ = document.createElement('span');\
            span.style.cssText = 'position: relative; left: -50%; top: -8px; white-space: nowrap; border: 1px solid blue; padding: 2px; background-color: white';\
            var div = this.div_ = document.createElement('div');\
            div.appendChild(span);\
            div.style.cssText = 'position: absolute; display: none';\
        }\
        Label.prototype = new google.maps.OverlayView();\
\
        Label.prototype.onAdd = function() {\
            var pane = this.getPanes().floatPane;\
            pane.appendChild(this.div_);\
            var me = this;\
            this.listeners_ = [\
                google.maps.event.addListener(this, 'position_changed', function() { me.draw();}),\
                google.maps.event.addListener(this, 'text_changed', function() { me.draw();})\
            ];\
        };\
        Label.prototype.onRemove = function() {\
            this.div_.parentNode.removeChild(this.div_);\
            for (var i = 0, max = this.listeners_.length; i < max; i++)\
                google.maps.event.removeListener(this.listeners_[i]);\
        };\
        Label.prototype.draw = function() {\
            var projection = this.getProjection();\
            var position = projection.fromLatLngToDivPixel(this.get('position'));\
            var div = this.div_;\
            div.style.left = position.x + 'px';\
            div.style.top = position.y + 'px';\
            div.style.display = 'block';\
        };\
\
        window.onload = function() {\
            var map = new google.maps.Map(document.getElementById(\"MTR\"));\
            var info = new google.maps.InfoWindow();\
            var bounds = new google.maps.LatLngBounds();\
\
            for (i = 0; i < hopes.length; i++) {\
                var marker = new google.maps.Marker({\
                    position: new google.maps.LatLng(hopes[i].lat, hopes[i].lng),\
                    title: hopes[i].title,\
                    map: map,\
                });\
                bounds.extend(marker.position);\
                if (i > 0) {\
                    label = new Label({  \
                        map: map, position: google.maps.geometry.spherical.interpolate(\
                            new google.maps.LatLng(hopes[i - 1].lat, hopes[i - 1].lng),\
                            new google.maps.LatLng(hopes[i].lat, hopes[i].lng),\
                            0.5),\
                    });\
                    label.span_.innerHTML = hopes[i].delay;\
                }\
                (function(m, h) {\
                    google.maps.event.addListener(marker, \"click\", function (e) {\
                        info.setContent(h.desc);\
                        info.open(map, m);\
                    });\
                })(marker, hopes[i]);\
            }\
            map.fitBounds(bounds);\
            new google.maps.Polyline({\
                path: hopes,\
                strokeColor: '#1040F0',\
                strokeOpacity: 0.7,\
                geodesic: true,\
                map: map,\
            });\
\
        }\
    </script>\
    <div id=\"MTR\" style=\"width: 100%; height: 100%;\"></div>\
</body>\
</html>\
";

#ifdef IIDEBUG
#define TMP_WRITE(x) \
    if (write(tmpfd, x, strlen(x)) < -1) {\
		IIDEBUG_MSG((LOG_INFO, "ii_gen_n_open_html(): write() failed: %s", strerror(errno)));\
        return -1;\
    }
#else
#define TMP_WRITE(x) if (write(tmpfd, x, strlen(x)) < -1) return -1;
#endif

int ii_gen_n_open_html(int mode) {
    static int geo_ndx[][5] = {
        // lat, lng, city, region, country
        { 7, 8, 4, 3, 1 },	// y6
        { 6, 7, 4, 3, 0 },	// y7
        { 11, 12, 8, 4, 2 },	// y8
        { 3, 3, 0, 1, 2 },	// y9
    };

    char filename[] = TMPFILE;
    if (tmpfd) {
        close(tmpfd);
#ifndef IIDEBUG
        if (unlink(tmpfn) < 0)
            return -1;
#endif
    }
    if ((tmpfd = mkstemp(filename)) < -1) {
        IIDEBUG_MSG((LOG_INFO, "mkstemp() failed: %s", strerror(errno)));
        return -1;
    }
    strncpy(tmpfn, filename, sizeof(tmpfn));

    static char buf[1024];
    snprintf(buf, sizeof(buf), "<html><head><title>mtr%s</title></head>", mtr_args);
    TMP_WRITE(buf);
    TMP_WRITE(hbody_begin);

    int at, max = net_max();
    for (at = net_min(); at < max; at++) {
        ip_t *addr = net_addr(at);
        if (addrcmp((void *)addr, (void *)&unspec_addr, af) != 0) {
//{ lat: N.M, lng: K.L, title: 'ip (hostname)', delay: 'N msec', desc: 'City, Region, Country'},
            char *lat, *lng;
            if (geo_ndx[mode][0] != geo_ndx[mode][1]) {
                lat = get_ipinfo(addr, geo_ndx[mode][0]);
                lng = get_ipinfo(addr, geo_ndx[mode][1]);
            } else {
                char* ln[2] = { get_ipinfo(addr, geo_ndx[mode][0]) };
                if (split_with_sep(ln, 2, COMMA, 0) != 2)
                    continue;
                lat = ln[0];
                lng = ln[1];
            }
            char *city = get_ipinfo(addr, geo_ndx[mode][2]);
            char *region = get_ipinfo(addr, geo_ndx[mode][3]);
            char *country = get_ipinfo(addr, geo_ndx[mode][4]);
            if (!lat || !lng)
                continue;
            int l = 0;
            l += snprintf(buf + l, sizeof(buf) - l, "{ lat: %s, lng: %s, title: '%s", lat, lng, strlongip(addr));
            char *host = dns_lookup(addr);
            if (host)
                l += snprintf(buf + l, sizeof(buf) - l, " (%s)", host);
            l += snprintf(buf + l, sizeof(buf) - l, "', delay: '%.1f msec', desc: \"", net_avg(at) / 1000.);

            if (city)
                if (*city)
                    l += snprintf(buf + l, sizeof(buf) - l, "%s, ", city);
            if (region)
                if (*region)
                    l += snprintf(buf + l, sizeof(buf) - l, "%s, ", region);
            l += snprintf(buf + l, sizeof(buf) - l, "%s\"},", country);
            IIDEBUG_MSG((LOG_INFO, "map hope: %s", buf));
            TMP_WRITE(buf);
        }
    }

    TMP_WRITE(hbody_end);
    snprintf(buf, sizeof(buf), "xdg-open %s", filename); // "x-www-browser %s"
    return system(buf);
}

void ii_action(int action_asn) {
    if (ipinfo_no[0] >= 0) {
        switch (action_asn) {
            case ActionAS:	// `z' `Z'
                enable_ipinfo = !enable_ipinfo;
                break;
            case ActionII: {	// `y'
                int i;
                enable_ipinfo = 1;
                for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++) {
                    ipinfo_no[i]++;
                    if (ipinfo_no[i] > ipinfo_max)
                        ipinfo_no[i] = 0;
                    if (ipinfo_no[i] == ipinfo_max)
                        enable_ipinfo = 0;
                }
               break;
               }
            case ActionII_Map:	// `Y'
               switch (origin_no) {
                   case 5:
                   case 6:
                   case 7:
                   case 8:
                       ii_gen_n_open_html(origin_no - 5);
		       break;
		   default:
                       fprintf(stderr, "This experimental feature works in -y[6-9] modes only.");
	       }
               return;
        }
    } else // init
        ii_parsearg(NULL);

    if (!init)
        ii_open();
}

void query_iiaddr(ip_t *addr) {
  int i;
  for (i = 0; (i < II_ITEM_MAX) && (ipinfo_no[i] >= 0); i++)
    get_ipinfo(addr, ipinfo_no[i]);
}

void query_ipinfo(void) {
  if (!init)
      return;
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

