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

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "config.h"
#include "mtr.h"
#include "mtr-poll.h"
#include "net.h"
#include "display.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#include "ipinfo.h"

#if defined(LOG_IPINFO) && !defined(LOGMOD)
#define LOGMOD
#endif
#if !defined(LOG_IPINFO) && defined(LOGMOD)
#undef LOGMOD
#endif
#include "macros.h"

#define COMMA  ','
#define VSLASH '|'
#define UNKN   "?"
#define CHAR_QOUTES	  "\"'"
#define CHAR_BRACKETS "{}"
#define NETDATA_MAXSIZE   3000
#define TCP_RESP_LINES    100
#define TCP_CONN_TIMEOUT  3
#define WHOIS_COMMENT    '%'
#define WHOIS_LAST_NDX 2
#define HTTP_GET "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: mtr/%s\r\nAccept: */*\r\n\r\n"
#define IPINFO_TCP_TIMEOUT 10 /* in seconds */

struct ipitseq { int sock, state, slot; };
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
static struct ipitseq *ipitseq;        // for tcp-origins
static char exchbuf[NETDATA_MAXSIZE];  // send-receive buffer

// origin types: dns txt, http csv, whois pairs
enum { OT_DNS = 0 /*sure*/, OT_HTTP, OT_WHOIS };

typedef struct {
  char* host;
  char* host6;
  char* name[MAX_TXT_ITEMS];
  char* unkn;
  char  sep;
  int   type; // 0 - dns, 1 - http, 2 - whois
  int   skip_ndx[MAX_TXT_ITEMS]; // skip by index: 1, ...
  char* skip_str[MAX_TXT_ITEMS]; // skip by string: "query ip", ...
  char* prefix;
  int   width[MAX_TXT_ITEMS];
} origin_t;

#define ORIG_TYPE (origins[origin_no].type)
#define ORIG_HOST (origins[origin_no].host)
#define ORIG_UNKN (origins[origin_no].unkn)
#define ORIG_SKIP_NDX   (origins[origin_no].skip_ndx)
#define ORIG_SKIP_STR   (origins[origin_no].skip_str)
#define ORIG_NAME(num)  (origins[origin_no].name[num])
#define ORIG_WIDTH(num) (origins[origin_no].width[num])

static int ipinfo_no[MAX_TXT_ITEMS] = {-1}; // max is #8 getcitydetails.geobytes.com

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
    .sep   = COMMA, .type = OT_HTTP, .skip_ndx = {1, 14}, .prefix = "/csv/",
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
  int i, inside = 0;
  char *p, **a = args + 1;
  for (i = 0, p = *args; *p; p++)
    if ((*p == sep) && !inside) {
      i++;
      if (i >= max) break;
      *p = 0;
      *a++ = p + 1;
    } else if (*p == quote) inside = !inside;
  for (int j = 0; (j < max) && args[j]; j++)
    args[j] = trim(args[j]);
  return (i < max) ? (i + 1) : max;
}

static void unkn2norm(char **record) {
  if (ORIG_UNKN) { // change to std UNKN
    int len = strnlen(ORIG_UNKN, NAMELEN);
    for (int i = 0; (i < MAX_TXT_ITEMS) && record[i]; i++)
      if (!strncmp(record[i], ORIG_UNKN, len))
        record[i] = UNKN;
  }
}

static char** split_record(char *r) {
  static char* recbuf[MAX_TXT_ITEMS];
  memset(recbuf, 0, sizeof(recbuf));
  recbuf[0] = r;
  split_with_sep(recbuf, MAX_TXT_ITEMS, origins[origin_no].sep, '"');
  unkn2norm(recbuf);
  return recbuf;
}

static void adjust_width(char** record) {
  for (int i = 0; (i < MAX_TXT_ITEMS) && record[i]; i++) {
    int len = strnlen(record[i], NAMELEN); // utf8 ? strnlen() : mbstowcs(NULL, records[i], 0);
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
    char *s = trim(record[i]);
    if (str_in_skip_list(s, ORIG_SKIP_STR) >= 0) // skip it
      continue;
    if (RTXT_AT_NDX(at, ndx, j))
      free(RTXT_AT_NDX(at, ndx, j));
    RTXT_AT_NDX(at, ndx, j) = strndup(s, NAMELEN);
    if (!RTXT_AT_NDX(at, ndx, j)) {
      WARN_("[%d:%d:%d]: strndup()", at, ndx, j);
      break;
    }
    LOGMSG_("[%d] %s", j, RTXT_AT_NDX(at, ndx, j));
    j++;
  }
}

void save_txt_answer(int at, int ndx, const char *answer) {
  char *copy = NULL, **data = NULL;
  if (answer && strnlen(answer, NAMELEN)) {
    copy = strndup(answer, NAMELEN);
    if (!copy) {
      WARN_("[%d:%d]: strndup()", at, ndx);
      return;
    }
    data = split_record(copy);
  }
  if (data)
    save_fields(at, ndx, data);
  else {
    char* empty[MAX_TXT_ITEMS];
    memset(empty, 0, sizeof(empty));
    save_fields(at, ndx, empty); // it sets as unknown
  }
  if (copy)
    free(copy);
  adjust_width(&(RTXT_AT_NDX(at, ndx, 0)));
}

static char trim_c(char *s, char *sc) {
    char c;
    while ((c = *sc++)) if (*s == c) { *s = 0; break;}
    return (*s);
}

static char* trim_str(char *s, char *sc) {
    char *p;
    int i, l = strlen(s);
    for (i = l - 1, p = s + l - 1; i >= 0; i--, p--)
        if (trim_c(p, sc)) break;
    for (i = 0, p = s, l = strlen(s); i < l; i++, p++)
        if (trim_c(p, sc)) break;
    return p;
}

static void save_records(atndx_t id, char **record) {
  // save results of parsing
  save_fields(id.at, id.ndx, record);
  adjust_width(&(RTXT_AT_NDX(id.at, id.ndx, 0)));
}

static int count_records(char **r) {
  int n = 0;
  for (int i = 0; (i < MAX_TXT_ITEMS) && r[i]; i++) {
    if (ndx_in_skip_list(i, ORIG_SKIP_NDX) >= 0) // skip it
      continue;
    r[i] = trim(r[i]);
    if (str_in_skip_list(r[i], ORIG_SKIP_STR) >= 0) // skip it
      continue;
    n++;
  }
  return n;
}


static void parse_http(void *buf, int r, atndx_t id) {
  static char h11[] = "HTTP/1.1";
  static int h11_ln = sizeof(h11) - 1;
  static char h11ok[] = "HTTP/1.1 200 OK";
  static int h11ok_ln = sizeof(h11ok) - 1;

  LOGMSG_("got %d bytes: \"%s\"", r, (char*)buf);
  /*summ*/ ipinfo_replies[0]++; ipinfo_replies[1]++;

  for (char *p = buf; (p = strstr(p, h11)) && ((p - (char*)buf) < r); p += h11_ln) {
    if (strncmp(p, h11ok, h11ok_ln)) { // not HTTP OK
      LOGMSG_("not OK: %.*s", h11ok_ln, p);
      break; // i.e. set as unknown
    }
    char* lines[TCP_RESP_LINES];
    memset(lines, 0, sizeof(lines));
    lines[0] = buf;
    int rn = split_with_sep(lines, TCP_RESP_LINES, '\n', 0);
    if (rn < 4) { // HEADER + NL + NL + DATA
      LOGMSG_("No data after header (got %d lines only)", rn);
      continue;
    }

    int cndx = 0, clen = 0; // content index in tcpresp and its length
    for (int i = 0; i < rn; i++) {
      char* ln[2] = { lines[i] };
      if (split_with_sep(ln, 2, ' ', 0) == 2)
        if (strcmp("Content-Length:", ln[0]) == 0)
          clen = atoi(ln[1]);
      if (lines[i][0]) // skip header lines
        continue;
      if ((i + 1) < rn)
        cndx = i + 1;
      break;
    }
    if (cndx && (clen > 0) && (clen < r))
      *(lines[cndx] + clen) = 0;
    else
      clen = strnlen(lines[cndx], NAMELEN);

    char *txt = calloc(1, clen + 1);
    if (!txt) {
      WARN_("calloc(%d)", clen + 1);
      return;
    }
    for (int i = cndx, l = 0; (i < rn) && (l < clen); i++) // combine into one line
      l += snprintf(txt + l, clen - l, "%s", lines[i]);

    LOGMSG_("got line: %s", txt);
    char **re = split_record(trim_str(trim_str(txt, CHAR_QOUTES), CHAR_BRACKETS));
    if (re) {
      int got = count_records(re);
      if (got == itemname_max) { // save results and return
        save_records(id, re);
        free(txt);
        return;
      } else
        LOGMSG_("Expected %d records, got %d", itemname_max, got);
    }
    free(txt);
  }

  // not found
  char* empty[MAX_TXT_ITEMS];
  memset(empty, 0, sizeof(empty));
  save_records(id, empty); // it sets as unknown
}


static void parse_whois(void *txt, int r, atndx_t id) {
  LOGMSG_("got[%d]: \"%.*s\"", r, r, (char*)txt);
  /*summ*/ ipinfo_replies[0]++; ipinfo_replies[2]++;

  static char* record[MAX_TXT_ITEMS];
  memset(record, 0, sizeof(record));
  char* lines[TCP_RESP_LINES];
  memset(lines, 0, sizeof(lines));
  lines[0] = txt;

  int rn = split_with_sep(lines, TCP_RESP_LINES, '\n', 0);
  int sn = skip_whois_comments(lines, rn);
  if (sn >= 0) { // not empty segments
    for (int i = sn; (i < rn) && (i < TCP_RESP_LINES) && lines[i]; i++) {
      if (!lines[i][0] || (lines[i][0] == WHOIS_COMMENT))
        continue; // skip empty lines and comments
      char* ln[2] = { lines[i] };
      if (split_with_sep(ln, 2, ':', 0) == 2) {
        for (int j = 0; (j < MAX_TXT_ITEMS) && ORIG_NAME(j); j++) {
          if (!ln[0])
            break;
          if (af == AF_INET6) { // check "*6" fields too
            int lc = strnlen(ln[0], NAMELEN) - 1;
            if ((lc > 0) && (ln[0][lc] == '6'))
              ln[0][lc] = 0;
          }
          if (strcasecmp(ORIG_NAME(j), ln[0]) == 0)
            record[j] = ln[1];
          if (j == WHOIS_LAST_NDX) { // split the last item (description, country)
            char* dc[2] = { record[j] };
            if (split_with_sep(dc, 2, COMMA, 0) == 2)
              record[WHOIS_LAST_NDX + 1] = dc[1];
          }
        }
      }
    }
  } else
    LOGMSG("Skip empty segment");

  // save results of parsing
  save_records(id, record);
}


static void close_ipitseq(int seq) {
  int sock = ipitseq[seq].sock;
  if (sock >= 0) {
    if (ipitseq[seq].slot >= 0)
      poll_dereg_fd(ipitseq[seq].slot);
    else {
      LOGMSG_("close sock=%d", sock);
      close(sock);
      /*summ*/ sum_sock[1]++;
    }
    memset(&ipitseq[seq], -1, sizeof(struct ipitseq));
  }
}

void ipinfo_parse(int sock, int seq) { // except dns, dns.ack in dns.c
  seq %= MAXSEQ;
  memset(exchbuf, 0, sizeof(exchbuf));
  int r = recv(sock, exchbuf, NETDATA_MAXSIZE, 0);
  if (r > 0) {
    atndx_t id = { .at = seq / MAXPATH, .ndx = seq % MAXPATH };
    switch ORIG_TYPE {
      case OT_HTTP: parse_http(exchbuf, r, id); return;
      case OT_WHOIS: parse_whois(exchbuf, r, id); return;
    }
  } else if (r < 0)
    WARN_("seq=%d recv(sock=%d)", seq, sock);
  close_ipitseq(seq);
}


static int create_tcpsock(int seq) {
  uint16_t port = (ORIG_TYPE == OT_WHOIS) ? 43 : 80;
  char srv[8];
  snprintf(srv, sizeof(srv), "%u", port);
  LOGMSG_("%s:%s", ORIG_HOST, srv);
  struct addrinfo hints, *rp;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = af;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  int e = getaddrinfo(ORIG_HOST, srv, &hints, &rp);
  if (e || !rp)
    LOG_RE_(-1, "getaddrinfo(%s): %s", ORIG_HOST, gai_strerror(e));
  int rc = -1;
  int sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
  if (sock >= 0) {
    LOGMSG_("socket=%d open", sock);
    /*summ*/ sum_sock[0]++;
    if (fcntl(sock, F_SETFL, O_NONBLOCK) >= 0) {
      int slot = poll_reg_fd(sock, seq + MAXSEQ);
      if (slot >= 0) {
        ipitseq[seq] = (struct ipitseq) { .sock = sock, .slot = slot, .state = TSEQ_CREATED };
        connect(sock, rp->ai_addr, rp->ai_addrlen);
        LOGMSG_("send non-blocking connect via sock=%d", sock);
        rc = 0;
      } else
        LOGMSG_("no place in pool for sockets (host=%s)", ORIG_HOST);
    } else
      LOGMSG_("%s: fcntl", ORIG_HOST);
    if (rc != 0) {
      LOGMSG_("socket=%d close", sock);
      close(sock);
      /*summ*/ sum_sock[1]++;
    }
  } else
    LOGMSG_("%s: socket", ORIG_HOST);
  freeaddrinfo(rp);
  return rc;
}

static int send_tcp_query(int sock, const char *q) {
  (ORIG_TYPE == OT_WHOIS) ?
    snprintf(exchbuf, NETDATA_MAXSIZE, "%s\r\n", q) :
    snprintf(exchbuf, NETDATA_MAXSIZE, HTTP_GET, q, ORIG_HOST, MTR_VERSION);
  int len = strnlen(exchbuf, NETDATA_MAXSIZE);
  int rc = send(sock, exchbuf, len, 0);
  if (rc >= 0) {
    /*summ*/ ipinfo_queries[0]++; (ORIG_TYPE == OT_HTTP) ? ipinfo_queries[1]++ : ipinfo_queries[2]++;
  }
  LOGMSG_("[orig=%d sock=%d] q=\"%s\" rc=%d ts=%lld", origin_no, sock, q, rc, (long long)time(NULL));
  return rc;
}

static char* make_tcp_qstr(ip_t *ip) {
  static char mkqstr[NAMELEN];
  snprintf(mkqstr, sizeof(mkqstr), "%s%s", origins[origin_no].prefix, strlongip(ip));
  return mkqstr;
}

void ipinfo_seq_ready(int seq) {
  seq %= MAXSEQ;
  int at = seq / MAXPATH, ndx = seq % MAXPATH;
  LOGMSG_("seq=%d at=%d ndx=%d", seq, at, ndx);
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
      WARN_("[%d:%d]: strndup()", at, ndx);
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
  int at = seq / MAXPATH, ndx = seq % MAXPATH;
  int dt = time(NULL) - QTXT_TS_AT_NDX(at, ndx);
  if (dt <= IPINFO_TCP_TIMEOUT)
    return false;
  LOGMSG_("clean tcp seq=%d after %d sec", seq, IPINFO_TCP_TIMEOUT);
  close_ipitseq(seq);
  return true;
}

static char *get_ipinfo(int at, int ndx, int nd) {
  if (RTXT_AT_NDX(at, ndx, nd)) // already known
    return RTXT_AT_NDX(at, ndx, nd);
#ifdef ENABLE_IPV6
  if ((af == AF_INET6) && !origins[origin_no].host6) return NULL; else
#endif
  if (!ORIG_HOST) return NULL;
  ip_t *ip = &IP_AT_NDX(at, ndx);
  switch (ORIG_TYPE) {
    case OT_HTTP:
    case OT_WHOIS:
      ipinfo_lookup(at, ndx, make_tcp_qstr(ip));
      break;
#ifdef ENABLE_DNS
    default:  // dns
      ipinfo_lookup(at, ndx, ip2arpa(ip, ORIG_HOST, origins[origin_no].host6));
#endif
  }
  return NULL;
}


#define FIELD_FMT	"%%-%ds "
char* ipinfo_header(void) {
  static char iiheader[NAMELEN];
  iiheader[0] = 0;
  char fmt[16];
  for (int i = 0, l = 0; (i < MAX_TXT_ITEMS)
      && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
      && ORIG_NAME(ipinfo_no[i]) && (l < sizeof(iiheader)); i++) {
    snprintf(fmt, sizeof(fmt), FIELD_FMT, ORIG_WIDTH(ipinfo_no[i]));
    l += snprintf(iiheader + l, sizeof(iiheader) - l, fmt, ORIG_NAME(ipinfo_no[i]));
  }
  return iiheader;
}

int ipinfo_width(void) {
  int l = 0;
  for (int i = 0; (i < MAX_TXT_ITEMS)
      && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
      && (l < NAMELEN); i++)
    l += 1 + ORIG_WIDTH(ipinfo_no[i]);
  return l;
}

typedef int (*filler_fn)(char *buf, int sz, const char *data, int num, char ch);

int fmt_filler(char *buf, int sz, const char *data, int width, char ignore) {
  if (width) {
    char fmt[16];
    snprintf(fmt, sizeof(fmt), FIELD_FMT, width);
    return snprintf(buf, sz, fmt, data);
  }
  return snprintf(buf, sz, "%s ", data);
}

int sep_filler(char *buf, int sz, const char *data, int seq, char sep) {
  return seq ? snprintf(buf, sz, "%c\"%s\"", sep, data) : snprintf(buf, sz, "\"%s\"", data);
}

static char *fill_ipinfo(int at, int ndx, char sep) {
  static char fmtinfo[NAMELEN];
  fmtinfo[0] = 0;
  for (int i = 0, l = 0; (i < MAX_TXT_ITEMS)
      && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
      && (l < sizeof(fmtinfo)); i++) {
    const char *rec = addr_exist(&IP_AT_NDX(at, ndx)) ? get_ipinfo(at, ndx, ipinfo_no[i]) : NULL;
    filler_fn fn = sep ? sep_filler : fmt_filler;
    l += fn(fmtinfo + l, sizeof(fmtinfo) - l, rec ? rec : UNKN, sep ? i : ORIG_WIDTH(ipinfo_no[i]), sep);
  }
  return fmtinfo;
}

inline char *fmt_ipinfo(int at, int ndx) { return fill_ipinfo(at, ndx, 0); }
inline char *sep_ipinfo(int at, int ndx, char sep) { return fill_ipinfo(at, ndx, sep); }

bool ipinfo_ready(void) { return (enable_ipinfo && ii_ready); }

static bool alloc_ipitseq(void) {
  size_t sz = MAXHOST * MAXPATH * sizeof(struct ipitseq);
  ipitseq = malloc(sz);
  if (!ipitseq) {
    WARN_("tcpseq malloc(%zd)", sz);
    return false;
  }
  memset(ipitseq, -1, sz);
  LOGMSG_("allocated %zd bytes for tcp-sockets", sz);
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
  LOGMSG_("%s", ii_ready ? "ok" : "failed");
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
  char* args[MAX_TXT_ITEMS + 1];
  memset(args, 0, sizeof(args));
  if (arg) {
    args[0] = strdup(arg);
    if (!args[0]) {
      WARN_("strdup(%s)", arg);
      return false;
    }
    split_with_sep(args, MAX_TXT_ITEMS + 1, COMMA, 0);
    int max = sizeof(origins) / sizeof(origins[0]);
    int no = (args[0] && *args[0]) ? atoi(args[0]) : 1;
    if ((no > 0) && (no <= max)) {
      origin_no = no - 1;
      ipinfo_tcpmode = (ORIG_TYPE != OT_DNS);
    } else {
      free(args[0]);
      WARNX_("Out of source range[1..%d]: %d", max, no);
      return false;
    }
  } else
    return false;

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

  LOGMSG_("Source: %s%s%s", ORIG_HOST, origins[origin_no].host6 ? ", " : "",
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
    ip_t *addr = &CURRENT_IP(at);
    if (addr_exist(addr)) {
      query_iiaddr(at, host[at].current);
      for (int i = 0; i < MAXPATH; i++) {
        if (i == host[at].current)
          continue; // because already queried
        ip_t *ip = &IP_AT_NDX(at, i);
        if (addr_exist(ip))
          query_iiaddr(at, i);
      }
    }
  }
}

