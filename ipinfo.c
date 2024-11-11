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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>

#include "config.h"
#if defined(LOG_IPINFO) && !defined(LOGMOD)
#include <errno.h>
#define LOGMOD
#endif
#if !defined(LOG_IPINFO) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "common.h"

#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
#ifndef BIND_8_COMPAT
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <resolv.h>

#include "ipinfo.h"
#include "mtr-poll.h"
#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#include "aux.h"

enum { COMMA = ',', VSLASH = '|', WHOIS_COMMENT = '%' };
#define UNKN "?"
#define CHAR_QUOTES   "\"'"
#define CHAR_BRACKETS "{}"

enum { TCP_CONN_TIMEOUT = 3, IPINFO_TCP_TIMEOUT = 10 /* in seconds */ };
enum { TCP_RESP_LINES = 100, NETDATA_MAXSIZE = 3000 };
enum { WHOIS_LAST_NDX = 2 };
#define HTTP_GET "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"

typedef struct { int sock, state, slot; } ipitseq_t;
enum { TSEQ_CREATED, TSEQ_READY };  // tcp-socket state: created or ready, otherwise -1

// global
bool enable_ipinfo;   // disabled by default
bool ipinfo_tcpmode;  // true if ipinfo origin is tcp (http or whois)
unsigned ipinfo_queries[3];  // number of queries (sum, http, whois)
unsigned ipinfo_replies[3];  // number of replies (sum, http, whois)
//

static bool ii_ready;
static int origin_no;     // set once at init
static int itemname_max;  // set once at init

static int ipinfo_syn_timeout = 3;     // in seconds
static ipitseq_t *ipitseq;             // for tcp-origins

// origin types: dns txt, http csv, whois pairs
enum { OT_DNS = 0 /*sure*/, OT_HTTP, OT_WHOIS };
enum { WHOIS_PORT = 43, HTTP_PORT = 80 };

typedef struct {
  char* host;
  char* host6;
  char* unkn;
  char* prefix;
  char* name[MAX_TXT_ITEMS];
  char* skip_str[MAX_TXT_ITEMS]; // skip by string: "query ip", ...
  int   type; // 0 - dns, 1 - http, 2 - whois
  int   skip_ndx[MAX_TXT_ITEMS]; // skip by index: 1, ...
  int   width[MAX_TXT_ITEMS];
  char  sep;
} origin_t;

#define ORIG_TYPE (origins[origin_no].type)
#define ORIG_HOST (origins[origin_no].host)
#define ORIG_UNKN (origins[origin_no].unkn)
#define ORIG_SKIP_NDX   (origins[origin_no].skip_ndx)
#define ORIG_SKIP_STR   (origins[origin_no].skip_str)
#define ORIG_NAME(num)  (origins[origin_no].name[num])
#define ORIG_WIDTH(num) (origins[origin_no].width[num])

static int ipinfo_no[MAX_TXT_ITEMS] = {-1}; // max is #8 getcitydetails.geobytes.com

enum { IPAPI_STATUS_NDX = 1, IPAPI_QUERYIP_NDX = 14};

static origin_t origins[] = {
// Abbreviations: CC - Country Code, RC - Region Code, MC - Metro Code, Org - Organization, TZ - TimeZone
// 1
  { .host  = "origin.asn.cymru.com", .host6 = "origin6.asn.cymru.com",
    .name  = { "ASN", "Route", "CC", "Registry", "Allocated" },
    .sep   = VSLASH,
  },
// 2
  { .host  =
#ifdef ENABLE_DNS
      "riswhois.ripe.net",
#else
      "193.0.11.5",
#endif
    .host6 =
#ifdef ENABLE_DNS
      "riswhois.ripe.net",
#else
      "2001:67c:2e8:25::c100:b05",
#endif
    .name  = {"Route", "Origin", "Descr", "CC"},
    .sep   = 0, .type = OT_WHOIS, .prefix = "-m ",
  },
// 3
  { .host  = "peer.asn.shadowserver.org",
    .name  = { "AS Path", "ASN", "Route", /*"AS Name",*/ "CC", "Org" },
    .sep   = VSLASH, .skip_ndx = {4},
  },
// 4
  { .host  = "origin.asn.spameatingmonkey.net",
    .name  = { "Route", "ASN", "Org", "Allocated", "CC" },
    .unkn  = "Unknown", .sep = VSLASH,
  },
// 5
  { .host  =
#ifdef ENABLE_DNS
      "ip-api.com",
#else
      "208.95.112.1",
#endif
    .name  = { /* Status, */ "Country", "CC", "RC", "Region", "City", "Zip", "Lat", "Long", "TZ", "ISP", "Org", "AS Name" /*, QueryIP */ },
    .sep   = COMMA, .type = OT_HTTP, .skip_ndx = {IPAPI_STATUS_NDX, IPAPI_QUERYIP_NDX}, .prefix = "/csv/",
  },
// 6
  { .host  = "asn.routeviews.org",
    .name  = { "ASN" },
    .unkn  = "4294967295",
  },
};

static int skip_whois_comments(char** lines, int max) {
  for (int i = 0; i < max; i++)
    if (lines[i] && lines[i][0] && (lines[i][0] != WHOIS_COMMENT))
      return i;
  return -1;
}

static int str_in_skip_list(const char *str, char* const* list) {
    for (int i = 0; (i < MAX_TXT_ITEMS) && list[i]; i++)
        if (strncmp(str, list[i], NAMELEN) == 0)
            return i;
    return -1;
}

static int ndx_in_skip_list(const int ndx, const int* list) {
    for (int i = 0; (i < MAX_TXT_ITEMS) && list[i]; i++)
        if ((ndx + 1) == list[i])
            return ndx;
    return -1;
}

static int split_with_sep(char** args, int max, char sep, char quote) {
  if (!args || !*args)
    return 0;
  int cnt = 0, inside = 0;
  for (char *ptr = *args, **next = args + 1; *ptr; ptr++) {
    if ((*ptr == sep) && !inside) {
      cnt++;
      if (cnt >= max) break;
      *ptr = 0;
      *next++ = ptr + 1;
    } else if (*ptr == quote)
      inside = !inside;
  }
  for (int j = 0; (j < max) && args[j]; j++)
    args[j] = trim(args[j]);
  return (cnt < max) ? (cnt + 1) : max;
}

static void unkn2norm(char **record) {
  if (ORIG_UNKN) { // change to std UNKN
    size_t len = strnlen(ORIG_UNKN, NAMELEN);
    for (int i = 0; (i < MAX_TXT_ITEMS) && record[i]; i++)
      if (!strncmp(record[i], ORIG_UNKN, len))
        record[i] = UNKN;
  }
}

static char** split_record(char *record) {
  static char* recbuf[MAX_TXT_ITEMS] = {0};
  recbuf[0] = record;
  split_with_sep(recbuf, MAX_TXT_ITEMS, origins[origin_no].sep, '"');
  unkn2norm(recbuf);
  return recbuf;
}

static void adjust_width(char** record) {
  for (int i = 0; (i < MAX_TXT_ITEMS) && record[i]; i++) {
    size_t len = strnlen(record[i], NAMELEN); // utf8 ? strnlen() : mbstowcs(NULL, records[i], 0);
    if (ORIG_WIDTH(i) < len)
      ORIG_WIDTH(i) = len;
  }
}

static void save_fields(int at, int ndx, char **record) {
  unkn2norm(record);
  for (int i = 0; i < itemname_max; i++)
    if (!record[i])
      record[i] = UNKN;
  for (int i = 0, j = 0; (i < MAX_TXT_ITEMS) && record[i]; i++) {
    if (ndx_in_skip_list(i, ORIG_SKIP_NDX) >= 0) // skip it
      continue;
    char *str = trim(record[i]);
    if (str_in_skip_list(str, ORIG_SKIP_STR) >= 0) // skip it
      continue;
    if (RTXT_AT_NDX(at, ndx, j))
      free(RTXT_AT_NDX(at, ndx, j));
    RTXT_AT_NDX(at, ndx, j) = strndup(str, NAMELEN);
    if (!RTXT_AT_NDX(at, ndx, j)) {
      WARN("[%d:%d:%d]: strndup()", at, ndx, j);
      break;
    }
    LOGMSG("[%d] %s", j, RTXT_AT_NDX(at, ndx, j));
    j++;
  }
}

void save_txt_answer(int at, int ndx, const char *answer) {
  char *copy = NULL, **data = NULL;
  if (answer && strnlen(answer, NAMELEN)) {
    copy = strndup(answer, NAMELEN);
    if (!copy) {
      WARN("[%d:%d]: strndup()", at, ndx);
      return;
    }
    data = split_record(copy);
  }
  if (data)
    save_fields(at, ndx, data);
  else {
    char* empty[MAX_TXT_ITEMS] = {0};
    save_fields(at, ndx, empty); // it sets as unknown
  }
  if (copy)
    free(copy);
  adjust_width(&(RTXT_AT_NDX(at, ndx, 0)));
}

static char trim_c(char *str, const char *quotes) {
  char ch = 0;
  while ((ch = *quotes++)) if (*str == ch) { *str = 0; break; }
  return (*str);
}

static char* trim_str(char *str, const char *quotes) {
  { size_t len = strlen(str);
    char *ptr = str + len - 1;
    for (size_t i = len; i > 0; i--, ptr--)
      if (trim_c(ptr, quotes)) break; }
  { char *ptr = str;
    for (; ptr; ptr++)
      if (trim_c(ptr, quotes)) break;
    return ptr; }
}

static void save_records(atndx_t id, char **record) {
  // save results of parsing
  save_fields(id.at, id.ndx, record);
  adjust_width(&(RTXT_AT_NDX(id.at, id.ndx, 0)));
}

static int count_records(char **record) {
  int nth = 0;
  for (int i = 0; (i < MAX_TXT_ITEMS) && record[i]; i++) {
    if (ndx_in_skip_list(i, ORIG_SKIP_NDX) >= 0) // skip it
      continue;
    record[i] = trim(record[i]);
    if (str_in_skip_list(record[i], ORIG_SKIP_STR) >= 0) // skip it
      continue;
    nth++;
  }
  return nth;
}

static inline int parse_http_content_len(int lines_no, char* lines[TCP_RESP_LINES], int recv_size, int *cndx) {
  int ndx = 0, len = 0; // content index in tcp response and its length
  for (int i = 0; i < lines_no; i++) {
    char* tagvalue[2] = { lines[i], NULL };
    if (split_with_sep(tagvalue, 2, ' ', 0) == 2)
      if (strcmp("Content-Length:", tagvalue[0]) == 0)
        len = atoi(tagvalue[1]);
    if (lines[i][0]) // skip header lines
      continue;
    if ((i + 1) < lines_no)
      ndx = i + 1;
    break;
  }
  if (ndx && (len > 0) && (len < recv_size))
    *(lines[ndx] + len) = 0;
  else
    len = strnlen(lines[ndx], NAMELEN);
  if (cndx) *cndx = ndx;
  return len;
}


static void parse_http(char *buf, int recv_size, atndx_t id) {
  static char h11[] = "HTTP/1.1";
  static int h11_ln = sizeof(h11) - 1;
  static char h11ok[] = "HTTP/1.1 200 OK";
  static int h11ok_ln = sizeof(h11ok) - 1;

  /*summ*/ ipinfo_replies[0]++; ipinfo_replies[1]++;

  for (char *ptr = buf; (ptr = strstr(ptr, h11)) && ((ptr - buf) < recv_size); ptr += h11_ln) {
    if (strncmp(ptr, h11ok, h11ok_ln)) { // not HTTP OK
      LOGMSG("not OK: %.*s", h11ok_ln, ptr);
      break; // i.e. set as unknown
    }
    char* lines[TCP_RESP_LINES] = {0};
    lines[0] = buf;
    int lines_no = split_with_sep(lines, TCP_RESP_LINES, '\n', 0);
    if (lines_no < 4) { // HEADER + NL + NL + DATA
      LOGMSG("No data after header (got %d lines only)", lines_no);
      continue;
    }

    int cndx = 0;
    int clen = parse_http_content_len(lines_no, lines, recv_size, &cndx);

    char txt[clen + 1]; memset(txt, 0, sizeof(txt));
    for (int i = cndx, len = 0; (i < lines_no) && (len < clen); i++) // combine into one line
      len += snprintf(txt + len, clen - len, "%s", lines[i]);

    LOGMSG("record line: %s", txt);
    char **records = split_record(trim_str(trim_str(txt, CHAR_QUOTES), CHAR_BRACKETS));
    if (records) {
      int got = count_records(records);
      if (got == itemname_max) { save_records(id, records); return; }
      LOGMSG("Expected %d records, got %d", itemname_max, got);
    }
  }

  // not found
  char* empty[MAX_TXT_ITEMS] = {0};
  save_records(id, empty); // it sets as unknown
}


static inline void parse_whois_tagvalue(char* line, char* record[MAX_TXT_ITEMS]) {
  char* tagvalue[2] = { line, NULL };
  if (split_with_sep(tagvalue, 2, ':', 0) != 2) return;
  for (int j = 0; (j < MAX_TXT_ITEMS) && ORIG_NAME(j); j++) {
    if (!tagvalue[0]) return;
    if (af == AF_INET6) { // check "*6" fields too
      size_t end = strnlen(tagvalue[0], NAMELEN) - 1;
      if ((end > 0) && (tagvalue[0][end] == '6'))
        tagvalue[0][end] = 0;
    }
    if (strcasecmp(ORIG_NAME(j), tagvalue[0]) == 0) record[j] = tagvalue[1];
    if (j == WHOIS_LAST_NDX) { // split the last item (description, country)
      char* desc_cc[2] = { record[j], NULL };
      if (split_with_sep(desc_cc, 2, COMMA, 0) == 2)
        record[WHOIS_LAST_NDX + 1] = desc_cc[1];
    }
  }
}


static void parse_whois(void *txt, atndx_t id) {
  /*summ*/ ipinfo_replies[0]++; ipinfo_replies[2]++;

  char* record[MAX_TXT_ITEMS] = {0};
  char* lines[TCP_RESP_LINES] = {0};
  lines[0] = txt;

  int lines_no = split_with_sep(lines, TCP_RESP_LINES, '\n', 0);
  int start_no = skip_whois_comments(lines, lines_no);
  if (start_no >= 0) { // not empty segments
    for (int i = start_no; (i < lines_no) && (i < TCP_RESP_LINES) && lines[i]; i++) {
      if (!lines[i][0] || (lines[i][0] == WHOIS_COMMENT))
        continue; // skip empty lines and comments
      parse_whois_tagvalue(lines[i], record);
    }
  } else LOGMSG("Skip empty segment");

  // save results of parsing
  save_records(id, record);
}


static void close_ipitseq(int seq) {
  int sock = ipitseq[seq].sock;
  if (sock >= 0) {
    if (ipitseq[seq].slot >= 0)
      poll_dereg_fd(ipitseq[seq].slot);
    else {
      LOGMSG("close sock=%d", sock);
      close(sock);
      /*summ*/ sum_sock[1]++;
    }
    memset(&ipitseq[seq], -1, sizeof(ipitseq[0]));
  }
}

void ipinfo_parse(int sock, int seq) { // except dns, dns.ack in dns.c
  char buf[NETDATA_MAXSIZE] = {0};
  seq %= MAXSEQ;
  int received = recv(sock, buf, sizeof(buf), 0);
  if (received > 0) {
    atndx_t id = { .at = seq / MAXPATH, .ndx = seq % MAXPATH };
    switch ORIG_TYPE {
      case OT_HTTP:
        LOGMSG( "HTTP: got[%d]: \"%.*s\"", received, received, buf);
        parse_http(buf, received, id);
        return;
      case OT_WHOIS:
        LOGMSG("WHOIS: got[%d]: \"%.*s\"", received, received, buf);
        parse_whois(buf, id);
        return;
      default: break;
    }
  } else if (received < 0)
    WARN("seq=%d recv(sock=%d)", seq, sock);
  close_ipitseq(seq);
}


static int create_tcpsock(int seq) {
  uint16_t port = (ORIG_TYPE == OT_WHOIS) ? WHOIS_PORT : HTTP_PORT;
  char srv[8];
  snprintf(srv, sizeof(srv), "%u", port);
  LOGMSG("%s:%s", ORIG_HOST, srv);
  struct addrinfo *rp = NULL, hints = {
    .ai_family = af,
    .ai_socktype = SOCK_STREAM,
    .ai_protocol = IPPROTO_TCP };
  int ecode = getaddrinfo(ORIG_HOST, srv, &hints, &rp);
  if (ecode || !rp)
    LOG_RE(-1, "getaddrinfo(%s): %s", ORIG_HOST, gai_strerror(ecode));
  int rc = -1;
  int sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
  if (sock < 0) {
    LOGMSG("%s: socket: %s", ORIG_HOST, strerror(errno));
  } else {
    LOGMSG("socket=%d open", sock);
    /*summ*/ sum_sock[0]++;
    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) {
      LOGMSG("%s: fcntl: %s", ORIG_HOST, strerror(errno));
    } else {
      int slot = poll_reg_fd(sock, seq + MAXSEQ);
      if (slot < 0) {
        LOGMSG("no place in pool for sockets (host=%s)", ORIG_HOST);
      } else {
        ipitseq[seq] = (ipitseq_t) { .sock = sock, .slot = slot, .state = TSEQ_CREATED };
        connect(sock, rp->ai_addr, rp->ai_addrlen); // NOLINT(bugprone-unused-return-value)
        LOGMSG("send non-blocking connect via sock=%d", sock);
        rc = 0; // note: non-blocking connect() returns EINPROGRESS
      }
    }
    if (rc) {
      LOGMSG("socket=%d close", sock);
      close(sock);
      /*summ*/ sum_sock[1]++;
    }
  }
  freeaddrinfo(rp);
  return rc;
}

static int send_tcp_query(int sock, const char *q) {
  char buf[NETDATA_MAXSIZE] = {0};
  (ORIG_TYPE == OT_WHOIS) ?
    snprintf(buf, sizeof(buf), "%s\r\n", q) :
    snprintf(buf, sizeof(buf), HTTP_GET, q, ORIG_HOST, PACKAGE_NAME);
  size_t len = strnlen(buf, sizeof(buf));
  int rc = send(sock, buf, len, 0);
  if (rc >= 0) {
    /*summ*/ ipinfo_queries[0]++; (ORIG_TYPE == OT_HTTP) ? ipinfo_queries[1]++ : ipinfo_queries[2]++;
  }
  LOGMSG("[orig=%d sock=%d] q=\"%s\" rc=%d ts=%lld", origin_no, sock, q, rc, (long long)time(NULL));
  return rc;
}

static char* make_tcp_qstr(t_ipaddr *ipaddr) {
  static char mkqstr[NAMELEN];
  snprintf(mkqstr, sizeof(mkqstr), "%s%s", origins[origin_no].prefix, strlongip(ipaddr));
  return mkqstr;
}

void ipinfo_seq_ready(int seq) {
  seq %= MAXSEQ;
  int at = seq / MAXPATH, ndx = seq % MAXPATH;
  LOGMSG("seq=%d at=%d ndx=%d", seq, at, ndx);
  ipitseq[seq].state = TSEQ_READY;
  QTXT_TS_AT_NDX(at, ndx) = time(NULL); // save send-time
  send_tcp_query(ipitseq[seq].sock, make_tcp_qstr(&IP_AT_NDX(at, ndx)));
}

static int ipinfo_lookup(int at, int ndx, const char *qstr) {
  if (!enable_ipinfo) // not enabled
    return -1;
  if (!addr_exist(&IP_AT_NDX(at, ndx))) // on the off chance
    return -1;
  if (RTXT_AT_NDX(at, ndx, 0)) // already known
    return -1;

  // set query string if not yet (setting a new ip, free this query)
  if (!QTXT_AT_NDX(at, ndx)) {
    QTXT_AT_NDX(at, ndx) = strndup(qstr, NAMELEN);
    if (!QTXT_AT_NDX(at, ndx)) {
      WARN("[%d:%d]: strndup()", at, ndx);
      return -1;
  }}

  int pause = PAUSE_BETWEEN_QUERIES;
  int seq = at * MAXPATH + ndx;
  if (ORIG_TYPE != OT_DNS) {
    if (!ipitseq)
      return -1;
    if (ipitseq[seq].state != TSEQ_READY)
      pause = ipinfo_syn_timeout;
  }

  time_t now = time(NULL);
  time_t dt_txt = now - QTXT_TS_AT_NDX(at, ndx);
  time_t dt_ptr = now - QPTR_TS_AT_NDX(at, ndx);
  if ((dt_txt < pause) || (dt_ptr < TXT_PTR_PAUSE))
    return -1; // too often
  QTXT_TS_AT_NDX(at, ndx) = now; // save time of trying to send something

  if (ORIG_TYPE != OT_DNS) { // tcp
    int state = ipitseq[seq].state;
    if (state != TSEQ_READY) {
      if (state != -1)
        close_ipitseq(seq);
      return create_tcpsock(seq);
    }
  }

  return
#ifdef ENABLE_DNS
    (ORIG_TYPE == OT_DNS) ? dns_send_query(at, ndx, qstr, T_TXT) :
#endif
    send_tcp_query(ipitseq[seq].sock, qstr);
}

bool ipinfo_timedout(int seq) {
  seq %= MAXSEQ;
  if ((time(NULL) - QTXT_TS_AT_NDX(seq / MAXPATH, seq % MAXPATH)) <= IPINFO_TCP_TIMEOUT)
    return false;
  LOGMSG("clean tcp seq=%d after %d sec", seq, IPINFO_TCP_TIMEOUT);
  close_ipitseq(seq);
  return true;
}

static char *get_ipinfo(int at, int ndx, int item_no) {
  if (RTXT_AT_NDX(at, ndx, item_no)) // already known
    return RTXT_AT_NDX(at, ndx, item_no);
#ifdef ENABLE_IPV6
  if (af == AF_INET6) {
    if (!origins[origin_no].host6) return NULL;
  } else
#endif
  { if (!ORIG_HOST) return NULL; }
  t_ipaddr *ipaddr = &IP_AT_NDX(at, ndx);
  switch (ORIG_TYPE) {
    case OT_HTTP:
    case OT_WHOIS:
      ipinfo_lookup(at, ndx, make_tcp_qstr(ipaddr));
      break;
#ifdef ENABLE_DNS
    default:  // dns
      ipinfo_lookup(at, ndx, ip2arpa(ipaddr, ORIG_HOST, origins[origin_no].host6));
#endif
  }
  return NULL;
}


char* ipinfo_header(void) {
  static char iiheader[NAMELEN];
  iiheader[0] = 0;
  for (int i = 0, len = 0; (i < MAX_TXT_ITEMS)
      && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
      && ORIG_NAME(ipinfo_no[i]) && (len < sizeof(iiheader)); i++) {
    len += snprintf(iiheader + len, sizeof(iiheader) - len,
      "%-*s ", ORIG_WIDTH(ipinfo_no[i]), ORIG_NAME(ipinfo_no[i]));
  }
  return iiheader;
}

int ipinfo_width(void) {
  int width = 0;
  for (int i = 0; (i < MAX_TXT_ITEMS)
      && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
      && (width < NAMELEN); i++)
    width += 1 + ORIG_WIDTH(ipinfo_no[i]);
  return width;
}

typedef int (*filler_fn)(char *buf, int size, const char *data, int num, char ch);

int fmt_filler(char *buf, int size, const char *data, int width, char ignore) {
  if (width) return snprintf(buf, size, "%-*s ", width, data);
  return snprintf(buf, size, "%s ", data);
}

int sep_filler(char *buf, int size, const char *data, int seq, char sep) {
  return seq ? snprintf(buf, size, "%c\"%s\"", sep, data) : snprintf(buf, size, "\"%s\"", data);
}

static char *fill_ipinfo(int at, int ndx, char sep) {
  static char fmtinfo[NAMELEN];
  fmtinfo[0] = 0;
  for (int i = 0, len = 0; (i < MAX_TXT_ITEMS)
      && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
      && (len < sizeof(fmtinfo)); i++) {
    const char *rec = addr_exist(&IP_AT_NDX(at, ndx)) ?
      get_ipinfo(at, ndx, ipinfo_no[i]) : NULL;
    filler_fn filler = sep ? sep_filler : fmt_filler;
    len += filler(fmtinfo + len, sizeof(fmtinfo) - len,
      rec ? rec : UNKN, sep ? i : ORIG_WIDTH(ipinfo_no[i]), sep);
  }
  return fmtinfo;
}

inline char *fmt_ipinfo(int at, int ndx) { return fill_ipinfo(at, ndx, 0); }
inline char *sep_ipinfo(int at, int ndx, char sep) { return fill_ipinfo(at, ndx, sep); }

bool ipinfo_ready(void) { return (enable_ipinfo && ii_ready); }

static bool alloc_ipitseq(void) {
  size_t size = sizeof(ipitseq_t) * MAXHOST * MAXPATH;
  ipitseq = malloc(size);
  if (!ipitseq) {
    WARN("tcpseq malloc(%zd)", size);
    return false;
  }
  memset(ipitseq, -1, size);
  LOGMSG("allocated %zd bytes for tcp-sockets", size);
  return true;
}

static void ipinfo_open(void) {
  if (ii_ready)
    return;
  ii_ready = true;
  if (ORIG_TYPE != OT_DNS) { // i.e. tcp (http or whois)
    if (!ipitseq && !alloc_ipitseq())
      ii_ready = false;
  } else
#ifdef ENABLE_DNS
    if (!dns_open())
#endif
    ii_ready = false;
#ifdef ENABLE_DNS
  dns_txt_handler = save_txt_answer; // handler is used in ipinfo only
#endif
  LOGMSG("%s", ii_ready ? "ok" : "failed");
}

void ipinfo_close(void) {
  if (ii_ready) {
    if (ipitseq) {
      for (int i = 0; i < MAXHOST * MAXPATH; i++)
        close_ipitseq(i);
      free(ipitseq);
      LOGMSG("free tcp-sockets memory");
    }
    ii_ready = false;
    LOGMSG("ok");
  }
#ifdef ENABLE_DNS
  if (ORIG_TYPE == OT_DNS)
    dns_close();
#endif
}

bool ipinfo_init(const char *arg) {
  if (!arg) return false;
  char* args[MAX_TXT_ITEMS + 1] = {0};

  args[0] = strdup(arg);
  if (!args[0]) { WARN("strdup(%s)", arg); return false; }
  split_with_sep(args, MAX_TXT_ITEMS + 1, COMMA, 0);
  int max = sizeof(origins) / sizeof(origins[0]);
  int no = (args[0] && *args[0]) ? atoi(args[0]) : 1;
  if ((no > 0) && (no <= max)) {
    origin_no = no - 1;
    ipinfo_tcpmode = (ORIG_TYPE != OT_DNS);
  } else {
    free(args[0]);
    WARNX("Out of source range[1..%d]: %d", max, no);
    return false;
  }

  int j = 0;
  for (int i = 1; (j < MAX_TXT_ITEMS) && (i <= MAX_TXT_ITEMS); i++)
    if (args[i]) {
      int no = atoi(args[i]);
      if (no > 0)
        ipinfo_no[j++] = no - 1;
    }
  for (int i = j; i < MAX_TXT_ITEMS; i++)
    ipinfo_no[i] = -1;
  if (ipinfo_no[0] < 0)
    ipinfo_no[0] = 0;

  if (args[0])
    free(args[0]);
  itemname_max = 0;
  for (int i = 0; i < MAX_TXT_ITEMS; i++, itemname_max++) {
    if (!ORIG_NAME(i))
      break;
    ORIG_WIDTH(i) = strnlen(ORIG_NAME(i), NAMELEN);
  }

  LOGMSG("Source: %s%s%s", ORIG_HOST, origins[origin_no].host6 ? ", " : "",
    origins[origin_no].host6 ? origins[origin_no].host6 : "");
  return true;
}


bool ipinfo_action(int action) {
  if (ipinfo_no[0] < 0) { // not at start, set default
    if (!ipinfo_init(ASLOOKUP_DEFAULT))
      return false;
  };
  if (!ii_ready)
    ipinfo_open();
  if (!ii_ready)
    return false;
  switch (action) {
    case ActionAS: // `z'
      enable_ipinfo = !enable_ipinfo;
      break;
    case ActionII: // `y'
      enable_ipinfo = true;
      for (int i = 0; (i < MAX_TXT_ITEMS) && (ipinfo_no[i] >= 0); i++) {
        ipinfo_no[i]++;
        if (ipinfo_no[i] > itemname_max)
          ipinfo_no[i] = 0;
        if (ipinfo_no[i] == itemname_max)
          enable_ipinfo = false;
      }
      break;
    case ActionNone: // first time
      enable_ipinfo = true;
    default: break;
  }
  return true;
}

static void query_iiaddr(int at, int ndx) {
  for (int i = 0; (i < MAX_TXT_ITEMS) && (ipinfo_no[i] >= 0); i++)
    get_ipinfo(at, ndx, ipinfo_no[i]);
}

void query_ipinfo(void) {
  if (!ii_ready)
      return;
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    t_ipaddr *ipaddr = &CURRENT_IP(at);
    if (addr_exist(ipaddr)) {
      query_iiaddr(at, host[at].current);
      for (int i = 0; i < MAXPATH; i++) {
        if (i == host[at].current)
          continue; // because already queried
        t_ipaddr *ipaddr_i = &IP_AT_NDX(at, i);
        if (addr_exist(ipaddr_i))
          query_iiaddr(at, i);
      }
    }
  }
}

