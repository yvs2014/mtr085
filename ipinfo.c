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
#include <sys/time.h>
#include <ctype.h>
#include <fcntl.h>

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
#include "ipinfo.h"

#ifdef LOG_IPINFO
#include <syslog.h>
#define IILOG_MSG(format, ...) { syslog(MTR_SYSLOG, format, __VA_ARGS__); }
#define IILOG_RET(format, ...) { syslog(MTR_SYSLOG, format, __VA_ARGS__); return; }
#else
#define IILOG_MSG(format, ...)  {}
#define IILOG_RET(format, ...)  { return; }
#endif

#define COMMA	','
#define VSLASH	'|'
#define II_RESP_LINES	100
#define NAMELEN	256
#define UNKN	"?"
#define RECV_BUFF_SZ	3000
#define TCP_CONN_TIMEOUT	3
#define CHAR_QOUTES	"\"'"
#define CHAR_BRACKETS	"{}"

extern struct __res_state _res;
extern char mtr_args[];

int enable_ipinfo;
int ipinfo_no[] = {-1};

static int init;
static int origin_no;
static int skipped_items;
static int skipped_props;

typedef char* items_t[IPINFO_MAX_ITEMS];
static items_t* items;
static int got_items;

typedef struct {
    int status;
    char *key;
} ii_q_t;

#define TMPFILE_BASE	"/tmp/mtr-map-XXXXXX"
#define TMPFILE_SUFF	".html"
#define TMPFILE	TMPFILE_BASE TMPFILE_SUFF

char tmpfn[] = TMPFILE;
static int tmpfd;
typedef char* tcp_resp_t[II_RESP_LINES];
static tcp_resp_t tcp_resp;
static char *last_request;	// workaround to "no id" whois

typedef void (*process_response_f)(void*, int);
static int remote_ports[] = { 53, 80, 80, 43 };	// [type]

typedef struct {
    char* host;
    char* host6;
    char* unkn;
    char sep;
    char* name[IPINFO_MAX_ITEMS];
    char* prop_prfx;
    int type;	// 0 - dns:csv, 1 - http:csv, 2 - http:flat-json, 3 - whois
    int ndx[IPINFO_MAX_ITEMS]; // skip/mandatory indexes: query ip, ...
    char* prefix;
    char* suffix;
    char* substitution[IPINFO_MAX_ITEMS];
    char* skip_prop[IPINFO_MAX_ITEMS]; // skip by string: query ip, ...
    int width[IPINFO_MAX_ITEMS];
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
        { "Peers", "ASN", "Route", "AS Name", "CC", /*"Website",*/ "Org" } },

    { "freegeoip.net", NULL, NULL, COMMA,
        { /* QueryIP, */ "CC", "Country", "RC", "Region", "City", "Zip", "TZ", "Lat", "Long", "MC" },
        NULL, 1, {1}, "/csv/" },

    { "ip-api.com", NULL, NULL, COMMA,
        { /* Status, */ "Country", "CC", "RC", "Region", "City", "Zip", "Lat", "Long", "TZ", "ISP", "Org", "AS Name" /*, QueryIP */ },
        NULL, 1, {14, 1}, "/csv/" },

    { "getcitydetails.geobytes.com", NULL, NULL, COMMA,
	    { /*forwarderfor, remoteip, ipaddress,*/ "certainty", "internet", "country", "regionlocationcode", "region", "code", "locationcode", "dma", "city", "cityid", "fqcn", "latitude", "longitude", "capital", "timezone", "nationalitysingular", "population", "nationalityplural", "mapreference", "currency", "currencycode", "title" },
        "geobytes", 2, {3}, "/GetCityDetails?fqcn=", NULL,
	    { "Certainty", "CC", "Country", "RLC", "Region", "RC", "LC", "DMA", "City", "CityID", "FQCN", "Lat", "Long", "Capital", "TZ", "Nationality", "Population", "NationalityPlural", "MapReference", "Currency", "CurrencyCode", "Title" },
        { "forwarderfor", "remoteip", "queryip" },
    },

    { "ipinfo.io", NULL, NULL, COMMA,
        { /* ip, hostname,*/ "city", "region", "country", "loc", "postal", "org" },
        NULL, 2, {1}, "/", "/json", { "City", "Region", "CC", "Location", "Postal", "Org"},
		{ "ip", "hostname" },
    },

    { "riswhois.ripe.net", "riswhois.ripe.net", NULL, 0,
        {"Route", "Origin", "Descr", "CC"},
        NULL, 3, {}, "-M " },
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
    for (j = 0; j < max; j++) {
        if (args[j])
            args[j] = trim(args[j]);
    }
    got_items = (i < max) ? (i + 1) : max;
    return got_items;
}

char* split_rec(char *rec) {
    IILOG_MSG("%s(%s)", __FUNCTION__, rec);
    if (!(items = malloc(sizeof(*items)))) {
        free(rec);
        IILOG_MSG("%s(): malloc() failed", __FUNCTION__);
        return NULL;
    }

    memset(items, 0, sizeof(*items));
    (*items)[0] = rec;
    int n = split_with_sep(*items, IPINFO_MAX_ITEMS, origins[origin_no].sep, '"');

    if (n > (ipinfo_max + skipped_items))
        ipinfo_max = n - ((skipped_items > skipped_props) ? skipped_items : skipped_props);

    char *unkn = origins[origin_no].unkn;
    if (unkn) {
        int len = strlen(unkn);
        int i;
        for (i = 0; (i < n) && (*items)[i]; i++)
            if (!strncmp((*items)[i], unkn, len))
                (*items)[i] = UNKN;
    }

    return (ipinfo_no[0] < n) ? (*items)[ipinfo_no[0]] : (*items)[0];
}

void add_rec(char *hkey) {
    if (origins[origin_no].ndx[0]) {
        items_t it;
        memcpy(&it, items, sizeof(it));
        memset(items, 0, sizeof(items_t));
        int i, j;
        for (i = j = 0; i < IPINFO_MAX_ITEMS; i++) {
            int k, skip = 0;
            if (origins[origin_no].type == 2) {	// http:flat-json 1st-slot
                if (!i && origins[origin_no].ndx[0])
                    continue;
            } else
                for (k = 0; (k < IPINFO_MAX_ITEMS) && origins[origin_no].ndx[k]; k++)
                    if ((skip = ((i + 1) == origins[origin_no].ndx[k]) ? 1 : 0))
                        break;
            if (!skip)
                (*items)[j++] = it[i];
        }
    }

    ENTRY *hr, item = { hkey, items};
    if (!(hr = hsearch(item, ENTER)))
        IILOG_RET("hsearch(ENTER, key=%s) failed: %s", hkey, strerror(errno));

#ifdef LOG_IPINFO
    static char buff[IPINFO_MAX_ITEMS * (NAMELEN + 1)];
    memset(buff, 0, sizeof(buff));
    int l = 0;
#endif
    int i;
    for (i = 0; (i < IPINFO_MAX_ITEMS) && (*items)[i]; i++) {
        int ilen = strnlen((*items)[i], NAMELEN);
//        int ilen = mbstowcs(NULL, (*items)[i], 0);	// utf8
        if (origins[origin_no].width[i] < ilen)
            origins[origin_no].width[i] = ilen;
#ifdef LOG_IPINFO
        l += snprintf(buff + l, sizeof(buff) - l, "\"%s\" ", (*items)[i]);
#endif
    }
    IILOG_MSG("Key %s: add %s", hkey, buff);
}

ENTRY* search_hashed_id(word id) {
    word ids[2] = { id, 0 };
    ENTRY *hr, item = { (void*)ids };
    if (!(hr = hsearch(item, FIND))) {
        IILOG_MSG("hsearch(FIND): key=%d not found", id);
        return NULL;
    }

    IILOG_MSG("Process ipinfo response id=%d", id);
    ((ii_q_t*)hr->data)->status = 1; // status: 1 (found)
    return hr;
}

void process_dns_response(void *buff, int r) {
    HEADER* header = (HEADER*)buff;
    ENTRY *hr;
    if (!(hr = search_hashed_id(header->id)))
        return;

    char hostname[NAMELEN], *txt;
    u_char *pt;
    int exp, size, txtlen, type;

    pt = buff + sizeof(HEADER);
    if ((exp = dn_expand(buff, buff + r, pt, hostname, sizeof(hostname))) < 0)
        IILOG_RET("%s(): dn_expand() failed: %s", __FUNCTION__, strerror(errno));

    pt += exp;
    GETSHORT(type, pt);
    if (type != T_TXT)
        IILOG_RET("%s(): broken DNS reply", __FUNCTION__);

    pt += INT16SZ; /* class */
    if ((exp = dn_expand(buff, buff + r, pt, hostname, sizeof(hostname))) < 0)
        IILOG_RET("%s(): second dn_expand() failed: %s", __FUNCTION__, strerror(errno));

    pt += exp;
    GETSHORT(type, pt);
    if (type != T_TXT)
        IILOG_RET("%s(): not a TXT record", __FUNCTION__);

    pt += INT16SZ; /* class */
    pt += INT32SZ; /* ttl */
    GETSHORT(size, pt);
    txtlen = *pt;
    if (txtlen >= size || !txtlen)
        IILOG_RET("%s(): broken TXT record (txtlen = %d, size = %d)", __FUNCTION__, txtlen, size);
    if (txtlen > NAMELEN)
        txtlen = NAMELEN;

    if (!(txt = malloc(txtlen + 1)))
        IILOG_RET("%s(): malloc() failed", __FUNCTION__);

    pt++;
    strncpy(txt, (char*) pt, txtlen);
    txt[txtlen] = 0;

    if (!split_rec(txt))
        return;
    add_rec(((ii_q_t*)hr->data)->key);
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

int in_str_list(const char *str, char* const* list) {
    int i;
    for (i = 0; (i < IPINFO_MAX_ITEMS) && list[i]; i++)
        if (strncmp(str, list[i], NAMELEN) == 0)
            return i;
    return -1;
}
int in_ndx_list(const int ndx, const int* list) {
    int i;
    for (i = 0; (i < IPINFO_MAX_ITEMS) && list[i]; i++)
        if ((ndx + 1) == list[i])
            return ndx;
    return -1;
}

void split_pairs(char sep) {
    items_t it;
    memcpy(&it, items, sizeof(it));
    memset(items, 0, sizeof(*items));
    int i;
    for (i = 0; (i < IPINFO_MAX_ITEMS) && it[i]; i++) {
        char* ln[2] = { it[i] };
        if (split_with_sep(ln, 2, sep, 0) != 2)
            continue;
        char *prop = trim_str(ln[0], CHAR_QOUTES);
        if (origins[origin_no].prop_prfx)
            if (strstr(prop, origins[origin_no].prop_prfx))
                prop += strlen(origins[origin_no].prop_prfx);
        char *val = trim_str(ln[1], CHAR_QOUTES);
        int ndx = in_ndx_list(i, origins[origin_no].ndx);
        if (ndx >= 0) {
            // type=2: http:flat-json: always add in 1st slot, it's query ip
            (*items)[(origins[origin_no].type == 2) ? 0 : ndx] = strdup(val);
            continue;
        }
        ndx = in_str_list(prop, origins[origin_no].name);
        if (ndx >= 0) {
            (*items)[ndx + skipped_items] = strdup(val);
            continue;
        }
    }

    for (i = 0; (i < IPINFO_MAX_ITEMS) && origins[origin_no].name[i]; i++) {
        if (!origins[origin_no].name[i])
            break;
        if (!(*items)[i])
            (*items)[i] = strdup("");
    }
}

void process_http_response(void *buff, int r) {
    static char h11[] = "HTTP/1.1";
    static int h11_ln = sizeof(h11) - 1;
    static char h11ok[] = "HTTP/1.1 200 OK";
    static int h11ok_ln = sizeof(h11ok) - 1;

    IILOG_MSG("Got[%d]: \"%s\"", r, (char*)buff);
#ifdef LOG_IPINFO
    int reply = 0;
#endif
    char *p;
    for (p = buff; (p = strstr(p, h11)); p += h11_ln) {	// parse pipelining chunks
#ifdef LOG_IPINFO
        reply++;
#endif
        if (!strncmp(p, h11ok, h11ok_ln)) {
            memset(tcp_resp, 0, sizeof(tcp_resp));
            static char copy[RECV_BUFF_SZ];
            memset(copy, 0, sizeof(copy));
            memcpy(copy, p, sizeof(copy));
            tcp_resp[0] = copy;

            int rn = split_with_sep(tcp_resp, II_RESP_LINES, '\n', 0);
            if (rn < 4) { // HEADER + NL + NL + DATA
                IILOG_MSG("%s(): empty response #%d", __FUNCTION__, reply);
                continue;
            }

            int content = 0, cnt_len = 0, i;
            for (i = 0; i < rn; i++) {
                char* ln[2] = { tcp_resp[i] };
                if (split_with_sep(ln, 2, ' ', 0) == 2)
                    if (strcmp("Content-Length:", ln[0]) == 0)
                        cnt_len = atoi(ln[1]);
                if (tcp_resp[i][0])	// skip header lines
                    continue;
                if ((i + 1) < rn)
                    content = i + 1;
                break;
            }
            if (content && (cnt_len > 0) && (cnt_len < r))
                *(tcp_resp[content] + cnt_len) = 0;
            else
                cnt_len = strlen(tcp_resp[content]);

            char *txt;
            if (!(txt = malloc(cnt_len + 1))) {
                IILOG_MSG("%s(): reply #%d: malloc() failed", __FUNCTION__, reply);
                continue;
            }
            memset(txt, 0, cnt_len);
            for (i = content; (i < rn) && (strlen(txt) < cnt_len); i++) { // combine into one line
                if (((tcp_resp[i] - tcp_resp[content]) + strlen(tcp_resp[i])) > cnt_len)
                    break;
                strcat(txt, tcp_resp[i]);
            }

            IILOG_MSG("http response#%d [%d]: \"%s\"", reply, rn, txt);
            if (!split_rec(trim_str(trim_str(txt, CHAR_QOUTES), CHAR_BRACKETS)))
                continue;
            else if (got_items < origins[origin_no].ndx[0]) {
                IILOG_MSG("%s(): got #%d, expected at least #%d", __FUNCTION__, got_items, origins[origin_no].ndx[0]);
                continue;
            }

            if (origins[origin_no].type == 2)
                split_pairs(':');

            { int j;
              for (j = 0; (j < IPINFO_MAX_ITEMS) && (*items)[j]; j++) // disclose items
                  (*items)[j] = trim_str((*items)[j], CHAR_QOUTES);
            }

            ENTRY *hr;
            // first entry is either our request or a return code
            int re_ndx = 0;
            if (origins[origin_no].type != 2)
                if (origins[origin_no].ndx[0])
                    re_ndx = origins[origin_no].ndx[0] - 1;
            if (!(hr = search_hashed_id(str2hash((*items)[re_ndx])))) {
                IILOG_MSG("%s(): got unknown reply #%d: \"%s\"", __FUNCTION__, reply, (*items)[re_ndx]);
                continue;
            }
            add_rec(((ii_q_t*)hr->data)->key);
        } else
            IILOG_MSG("%s(): reply#%d is not OK: got \"%s\"", __FUNCTION__, reply, p);
    }

#ifdef LOG_IPINFO
    if (!reply)
        IILOG_MSG("%s(): What is that? got[%d] \"%s\"", __FUNCTION__, r, (char*)buff);
#endif
}

void process_whois_response(void *buff, int r) {
    IILOG_MSG("Got[%d]: \"%s\"", r, (char*)buff);

    char *txt;
    if (!(txt = malloc(RECV_BUFF_SZ)))
        IILOG_RET("%s(): malloc() failed", __FUNCTION__);
    memcpy(txt, buff, RECV_BUFF_SZ);
    txt[r] = 0;

    if (!items) {
        if (!(items = malloc(sizeof(*items)))) {
            free(txt);
            IILOG_RET("%s(): malloc() failed", __FUNCTION__);
        }
        memset(items, 0, sizeof(*items));
    }

    memset(tcp_resp, 0, sizeof(tcp_resp));
    tcp_resp[0] = txt;

    int rn = split_with_sep(tcp_resp, II_RESP_LINES, '\n', 0);
    int i;
    for (i = 0; i < rn; i++) {
        char* ln[2] = { tcp_resp[i] };
//        IILOG_MSG("%s(): got#%d \"%s\"", __FUNCTION__, i, ln[0]);
        if (split_with_sep(ln, 2, ':', 0) == 2) {
            int j;
            for (j = 0; (j < IPINFO_MAX_ITEMS) && origins[origin_no].name[j]; j++) {
                char* desc = origins[origin_no].name[j];
                if (!desc)
                    break;
                if (strcasecmp(desc, ln[0]) == 0)
                    (*items)[j] = ln[1];
				else
                  if (af == AF_INET6) {	// check "*6" field names
                    char desc6[NAMELEN];
					snprintf(desc6, sizeof(desc6), "%s%s", desc, "6");
                    if (strcasecmp(desc6, ln[0]) == 0)
                      (*items)[j] = ln[1];
                  }
// riswhois: split the last item
#define RISWHOIS_LAST_NDX	2
                if (j == RISWHOIS_LAST_NDX) {	// "description, country"
                    char* dc[2] = { (*items)[j] };
                    if (split_with_sep(dc, 2, COMMA, 0) == 2)
                        (*items)[RISWHOIS_LAST_NDX + 1] = dc[1];
                }
                if (ipinfo_max < (j + 1))
                    ipinfo_max = j + 1;
            }
        }
    }

    ENTRY *hr;
    if (!(hr = search_hashed_id(str2hash(last_request))))
        IILOG_RET("%s(): got unknown reply: \"%s\"", __FUNCTION__, (char*)buff);

    for (i = 0; (i < IPINFO_MAX_ITEMS) && origins[origin_no].name[i]; i++)
        if (! ((*items)[i]))
            return;

    add_rec(((ii_q_t*)hr->data)->key);
    items = NULL;
}

static process_response_f process_response[] = { process_dns_response, process_http_response, process_http_response, process_whois_response };

void ii_ack(void) {
    static char buff[RECV_BUFF_SZ];
    int r = recv(origins[origin_no].fd, buff, sizeof(buff), 0);
    if (r > 0)
        process_response[origins[origin_no].type](buff, r);
    else if (r < 0)
        IILOG_RET("%s(): recv() failed: %s", __FUNCTION__, strerror(errno))
    else { // Got 0 bytes
        close(origins[origin_no].fd);
        origins[origin_no].fd = 0;
        last_request = NULL;
        IILOG_RET("Close connection to %s", origins[origin_no].host);
    }
}

int init_dns(void) {
    IILOG_MSG("%s", "Create DNS socket");
    if (res_init() < 0) {
        perror("res_init()");
        return -1;
    }
    if ((origins[origin_no].fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }
//    IILOG_MSG("DNS socket[origin=%d]: %d", origin_no, origins[origin_no].fd);
    return 0;
}

int open_tcp_connection(void) {
    IILOG_MSG("Open connection to %s", origins[origin_no].host);
    struct hostent* h;
    if (!(h = gethostbyname(origins[origin_no].host))) {
        perror(origins[origin_no].host);
        return -1;
    }

    struct sockaddr_in re;
    re.sin_family = AF_INET;
    re.sin_port = htons(remote_ports[origins[origin_no].type]);
    re.sin_addr = *(struct in_addr*)h->h_addr;
    memset(&re.sin_zero, 0, sizeof(re.sin_zero));

    int i, sock;
    for (i = sock = 0; h->h_addr_list[i]; i++) {
        re.sin_addr = *(struct in_addr*)h->h_addr_list[i];

        if (sock)
            close(sock);
        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket()");
            break;
        }
        if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
            perror("fcntl()");
            break;
        }

        int rv = connect(sock, (struct sockaddr*) &re, sizeof(struct sockaddr));
        if ((rv < 0) && (errno != EINPROGRESS)) {
            perror("connect()");
            continue;
        }
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        struct timeval tv = { TCP_CONN_TIMEOUT, 0 };
        if ((rv = select(sock + 1, NULL, &fds, NULL, &tv)) > 0) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (!so_error) {
                origins[origin_no].fd = sock;
                return 0;
            }
        } else if (rv < 0)
            perror("select()");
#ifdef LOG_IPINFO
        else
            IILOG_MSG("#%d: connection timed out", i);
#endif
    }
    fprintf(stderr, "Cannot create ipinfo connection\n");
    if (sock) {
       close(sock);
       origins[origin_no].fd = 0;
    }
    return -1;
}

typedef int (*open_connection_f)(void);
static open_connection_f open_connection[] = { init_dns, open_tcp_connection, open_tcp_connection, open_tcp_connection };

int send_dns_query(const char *request, word id) {
    unsigned char buff[RECV_BUFF_SZ];
    int r = res_mkquery(QUERY, request, C_IN, T_TXT, NULL, 0, NULL, buff, RECV_BUFF_SZ);
    if (r < 0) {
        IILOG_MSG("%s(): res_mkquery() failed: %s", __FUNCTION__, strerror(errno));
        return r;
    }
    HEADER* h = (HEADER*)buff;
    h->id = id;
    return sendto(origins[origin_no].fd, buff, r, 0, (struct sockaddr *)&_res.nsaddr_list[0], sizeof(struct sockaddr));
}

int send_http_query(const char *request, word id) {
    char buff[RECV_BUFF_SZ];
    snprintf(buff, sizeof(buff), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mtr/%s\r\nAccept: */*\r\n\r\n", request, origins[origin_no].host, MTR_VERSION);
    return send(origins[origin_no].fd, buff, strlen(buff), 0);
}

int send_whois_query(const char *request, word id) {
    char buff[RECV_BUFF_SZ];
    snprintf(buff, sizeof(buff), "%s\r\n", request);
    return send(origins[origin_no].fd, buff, strlen(buff), 0);
}

typedef int (*send_query_f)(const char*, word);
static send_query_f send_query[] = { send_dns_query, send_http_query, send_http_query, send_whois_query };

int ii_send_query(const char *lkey, const char *hkey) {
    word id[2] = { str2hash(hkey), 0 };
    ENTRY item = { (void*)id };
    if (hsearch(item, FIND)) {
//        IILOG_MSG("Query %s (id=%d) on the waitlist", lookup_key, id[0]);
        return 0;
    }

    int r;
    if (!origins[origin_no].fd)
        if ((r = open_connection[origins[origin_no].type]()) < 0)
            return r;

    IILOG_MSG("Send %s query (id=%d)", lkey, id[0]);
    if ((r = send_query[origins[origin_no].type](lkey, id[0])) <= 0)
        return r;

    if (!(item.key = malloc(sizeof(id))))
        return -1;
    memcpy(item.key, id, sizeof(id));
    if (!(item.data = malloc(sizeof(ii_q_t))))
        return -1;
    if (!(((ii_q_t*)item.data)->key = malloc(sizeof(hkey))))
        return -1;
    ((ii_q_t*)item.data)->status = 0; // status: 0 (query for)
    last_request = strdup(hkey);
    ((ii_q_t*)item.data)->key = last_request;

    IILOG_MSG("Add ipinfo query (id=%d, data=%s)", id[0], hkey);
    if (!hsearch(item, ENTER)) {
        IILOG_MSG("hsearch(ENTER, key=%d, data=%s) failed: %s", id[0], hkey, strerror(errno));
        return -1;
    }

    return 0;
}


#ifdef ENABLE_IPV6
#define BYTES_TO_PROCESS	8
void al_reves_chars(int al_reves, const unsigned char *s6a, int i, char *b0) {
    static char hex4bits[] = "0123456789abcdef";
    if (al_reves) {
        char c = s6a[BYTES_TO_PROCESS - 1 - i];
        *b0 = hex4bits[c & 0xf];
        *(b0 + 2) = hex4bits[(c >> 4) & 0xf];
    } else {
        char c = s6a[i];
        *b0 = hex4bits[(c >> 4) & 0xf];
        *(b0 + 2) = hex4bits[c & 0xf];
    }
    *(b0 + 1) = '.';
    *(b0 + 3) = '.';
}

char *al_reves_host6(struct in6_addr *addr, char *buff, int len, int dir) {	// 0: frontward, 1: backward
    if (len < (4 * BYTES_TO_PROCESS))
        return NULL;
    for (int i = 0; i < BYTES_TO_PROCESS; i++)
        al_reves_chars(dir, addr->s6_addr, i, buff + i * 4);
    buff[4 * BYTES_TO_PROCESS - 1] = 0;
    return buff;
}
#endif


void set_tcp_lkey(char *lkey, const char *hkey) {
  sprintf(lkey, "%s%s", origins[origin_no].prefix, hkey);
  if (origins[origin_no].suffix)
    sprintf(lkey + strlen(lkey), "%s", origins[origin_no].suffix);
}


char *get_ipinfo(ip_t *addr, int nd) {
    if (!addr)
        return NULL;
    static char hkey[NAMELEN];
    static char lkey[NAMELEN];

#ifdef ENABLE_IPV6
    if (af == AF_INET6) {
        if (!origins[origin_no].host6)
            return NULL;
        switch (origins[origin_no].type) {
            case 1: // http:csv
            case 2: // http:flat-json
            case 3: // whois
                set_tcp_lkey(lkey, strlongip(addr));
                break;
            default: { // dns
                char *al = al_reves_host6(addr, hkey, sizeof(hkey), 1);
                if (!al)
                    return NULL;
		if (snprintf(lkey, sizeof(lkey), "%s.%s", al, origins[origin_no].host6) < 0)
                    return NULL;
                }
        }
	if (!al_reves_host6(addr, hkey, sizeof(hkey), 0))
            return NULL;
    } else /* if (af == AF_INET) */
#endif
    {   if (!origins[origin_no].host)
            return NULL;
        snprintf(hkey, sizeof(hkey), "%d.%d.%d.%d", ((unsigned char*)addr)[0], ((unsigned char*)addr)[1], ((unsigned char*)addr)[2], ((unsigned char*)addr)[3]);
        switch (origins[origin_no].type) {
            case 1: // http:csv
            case 2: // http:flat-json
            case 3: // whois
                set_tcp_lkey(lkey, hkey);
                break;
            default: // dns
                snprintf(lkey, sizeof(lkey), "%d.%d.%d.%d.%s", ((unsigned char*)addr)[3], ((unsigned char*)addr)[2], ((unsigned char*)addr)[1], ((unsigned char*)addr)[0], origins[origin_no].host);
        }
    }

    ENTRY *hr, item = { hkey };
    if ((hr = hsearch(item, FIND)))
        return (*((items_t*)hr->data))[nd];
    else {
        if (origins[origin_no].type != 3)
            ii_send_query(lkey, hkey);
        else if (!last_request) // 4whois
            ii_send_query(lkey, hkey);
    }
    return NULL;
}


#define FIELD_FMT	"%%-%ds "
char* ii_getheader(void) {
    static char header[NAMELEN];
    char fmt[16];
    int i, l = 0;
    for (i = 0; i < IPINFO_MAX_ITEMS; i++) {
        int no = ipinfo_no[i];
        char *name = origins[origin_no].name[no];
        if ((no < 0) || (no >= ipinfo_max) || (l >= NAMELEN) || !name)
            break;
        snprintf(fmt, sizeof(fmt), FIELD_FMT, origins[origin_no].width[no]);
        char *sname = origins[origin_no].substitution[no];
        l += snprintf(header + l, sizeof(header) - l, fmt, sname ? sname : name);
    }
    return l ? header : NULL;
}

int ii_getwidth(void) {
    int i, l = 0;
    for (i = 0; (i < IPINFO_MAX_ITEMS) && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < ipinfo_max); i++)
        l += origins[origin_no].width[ipinfo_no[i]] + 1;
    return l;
}

char *fmt_ipinfo(ip_t *addr) {
    static char fmtinfo[NAMELEN];
    char fmt[16];
    int l = 0, i;
    for (i = 0; (i < IPINFO_MAX_ITEMS) && (ipinfo_no[i] >= 0); i++) {
        char *ipinfo = unaddrcmp(addr) ? get_ipinfo(addr, ipinfo_no[i]) : NULL;
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
   if (!hinit) {
       if (!hcreate(maxTTL * 4)) {
           perror("hcreate()");
           return;
       }
       hinit = 1;
   }
   if (open_connection[origins[origin_no].type]() < 0)
       return;
   while ((skipped_items < IPINFO_MAX_ITEMS) && origins[origin_no].ndx[skipped_items])
       skipped_items++;
   while ((skipped_props < IPINFO_MAX_ITEMS) && origins[origin_no].skip_prop[skipped_props])
       skipped_props++;

   int i;
   for (i = 0; i < IPINFO_MAX_ITEMS; i++) {
       if (!origins[origin_no].name[i])
           break;
       origins[origin_no].width[i] = strnlen(origins[origin_no].name[i], NAMELEN);
   }

   init = 1;
}

void ii_close(void) {
    if (origins[origin_no].fd)
        close(origins[origin_no].fd);
    if (hinit) {
        hdestroy();
        hinit = 0;
    }
    enable_ipinfo = 0;
    if (tmpfd) {
        close(tmpfd);
#ifndef LOG_IPINFO
        unlink(tmpfn);
#endif
    }
}

void ii_parsearg(char *arg) {
    char* args[IPINFO_MAX_ITEMS + 1];
    memset(args, 0, sizeof(args));
    if (arg) {
        args[0] = strdup(arg);
        split_with_sep(args, IPINFO_MAX_ITEMS + 1, COMMA, 0);
        int no = atoi(args[0]);
        if ((no > 0) && (no <= (sizeof(origins)/sizeof(origins[0]))))
            origin_no = no - 1;
    }

    int i, j;
    for (i = 1, j = 0; (j < IPINFO_MAX_ITEMS) && (i <= IPINFO_MAX_ITEMS); i++)
        if (args[i]) {
            int no = atoi(args[i]);
            if (no > 0)
                ipinfo_no[j++] = no - 1;
        }
    for (i = j; i < IPINFO_MAX_ITEMS; i++)
        ipinfo_no[i] = -1;
    if (ipinfo_no[0] < 0)
        ipinfo_no[0] = 0;

    if (args[0])
        free(args[0]);
    enable_ipinfo = 1;
    IILOG_MSG("Data source: %s/%s", origins[origin_no].host, origins[origin_no].host6?origins[origin_no].host6:"-");

    if (!init)
        ii_open();
}

char hhead_script[] = "<script src=\"https://unpkg.com/leaflet@1.4.0/dist/leaflet.js\"></script>";
char hhead_link[] = "<link rel=\"stylesheet\" href=\"https://unpkg.com/leaflet@1.4.0/dist/leaflet.css\">";
char hbody_begin[] =
"<body>"
"	<div id=\"mtr_div\" style=\"width:100%; height:100%;\"></div>"
"	<script>"
"		var hopes = [";
char hbody_end[] =
"		];"
"		var map = L.map('mtr_div');"
"		L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {"
"			attribution: '<a href=\"https://www.openstreetmap.org/\">OpenStreetMap</a>'"
"		}).addTo(map);"
"		hopes.forEach(function(e){"
"			m = L.marker(e).addTo(map);"
"			m.bindTooltip(e.delay + '<br>' + e.title + '<br>' + e.desc);"
"		});"
"		var polyline = L.polyline(hopes, {opacity:0.7,weight:5}).addTo(map);"
"		map.fitBounds(polyline.getBounds());"
"    </script>"
"</body>"
"</html>";

#ifdef LOG_IPINFO
#define TMP_WRITE(x) \
    if (write(tmpfd, x, strlen(x)) < -1) {\
		IILOG_MSG("%s(): write() failed: %s", __FUNCTION__, strerror(errno));\
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
#ifndef LOG_IPINFO
        if (unlink(tmpfn) < 0)
            return -1;
#endif
    }
    if ((tmpfd = mkstemps(filename, strlen(TMPFILE_SUFF))) < -1) {
        IILOG_MSG("mkstemp() failed: %s", strerror(errno));
        return -1;
    }
    strncpy(tmpfn, filename, sizeof(tmpfn));

    static char buf[1024];
    snprintf(buf, sizeof(buf), "<html><head><title>mtr%s</title>%s%s</head>", mtr_args, hhead_script, hhead_link);
    TMP_WRITE(buf);
    TMP_WRITE(hbody_begin);

    int at, max = net_max();
    for (at = net_min(); at < max; at++) {
        ip_t *addr = &host[at].addr;
        if (unaddrcmp(addr)) {
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
            const char *hostname = dns_lookup(addr);
            if (hostname)
                l += snprintf(buf + l, sizeof(buf) - l, " (%s)", hostname);
            l += snprintf(buf + l, sizeof(buf) - l, "', delay: '%.1f msec', desc: \"", host[at].avg / 1000.);

            if (city)
                if (*city)
                    l += snprintf(buf + l, sizeof(buf) - l, "%s, ", city);
            if (region)
                if (*region)
                    l += snprintf(buf + l, sizeof(buf) - l, "%s, ", region);
            l += snprintf(buf + l, sizeof(buf) - l, "%s\"},", country);
            IILOG_MSG("map hope: %s", buf);
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
                for (i = 0; (i < IPINFO_MAX_ITEMS) && (ipinfo_no[i] >= 0); i++) {
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
                       fprintf(stderr, "This experimental feature works in -y[6-9] modes only.\n");
	       }
               return;
        }
    } else // init
        ii_parsearg(ASLOOKUP_DEFAULT);

    if (!init)
        ii_open();
}

void query_iiaddr(ip_t *addr) {
  int i;
  for (i = 0; (i < IPINFO_MAX_ITEMS) && (ipinfo_no[i] >= 0); i++)
    get_ipinfo(addr, ipinfo_no[i]);
}

void query_ipinfo(void) {
  if (!init)
      return;
  int at, max = net_max();
  for (at = net_min(); at < max; at++) {
    ip_t *addr = &host[at].addr;
    if (unaddrcmp(addr)) {
      query_iiaddr(addr);
      int i;
      for (i=0; i < MAXPATH; i++) {
        ip_t *addrs = &(host[at].addrs[i]);
        if (unaddrcmp(addrs))
          query_iiaddr(addrs);
      }
    }
  }
}

