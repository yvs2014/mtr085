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
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_NETDB_H
  #include <netdb.h>
#endif

#include <resolv.h>

#ifdef HAVE_ARPA_NAMESER_H
  #include <arpa/nameser.h>
#endif

#if defined(LOG_IPINFO) && !defined(LOGMOD)
  #define LOGMOD
#endif
#if !defined(LOG_IPINFO) && defined(LOGMOD)
  #undef LOGMOD
#endif

#include "ipinfo.h"
#include "polling.h"
#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#include "aux.h"
#include "nls.h"

#define UNKN "?"
#define WHOIS_COMMENT PERCENT

enum { TCP_CONN_TIMEOUT = 3, IPINFO_TCP_TIMEOUT = 10 /* in seconds */ };
enum { TCP_RESP_LINES = 100, NETDATA_MAXSIZE = 3000 };
enum { WHOIS_LAST_NDX = 2 };
#define HTTP_GET "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n"

typedef struct { int sock, state, slot; } ipitseq_t;
enum { TSEQ_CREATED, TSEQ_READY };  // tcp-socket state: created or ready, otherwise -1

// global
bool ipinfo_tcpmode;     // true if ipinfo origin is tcp (http or whois)
uint ipinfo_queries[3];  // number of queries (sum, http, whois)
uint ipinfo_replies[3];  // number of replies (sum, http, whois)
bool ipinfo_rewidth;     // indicator to redraw titles
bool ipinfo_ready;
//

static int origin_no;     // set once at init
static int itemname_max;  // set once at init

static int ipinfo_syn_timeout = 3;     // in seconds
static ipitseq_t *ipitseq;             // for tcp-origins

// origin types: dns txt, http csv, whois pairs
enum { OT_DNS = 0 /*sure*/, OT_HTTP, OT_WHOIS };
enum { WHOIS_PORT = 43, HTTP_PORT = 80 };

#define SETFIELDS false
#define ADDFIELDS true

typedef struct {
  const char* host;
  const char* host6;
  const char* unkn;
  const char* prefix;
  const char* name[II_REC_ARR_LEN];
  const char* uname[II_REC_ARR_LEN];
  const char* skip_str[II_REC_ARR_LEN]; // skip by string: "query ip", ...
  int   asnth; // ASN-field-number in ipinfo field-list
  int   type; // 0 - dns, 1 - http, 2 - whois
  int   skip_ndx[II_REC_ARR_LEN]; // skip by index: 1, ...
  int   width[II_REC_ARR_LEN];
  char  sep;
  char  comb_last_fields;
} origin_t;

#define ORIG_TYPE (origins[origin_no].type)
#define ORIG_HOST (origins[origin_no].host)
#define ORIG_UNKN (origins[origin_no].unkn)
#define ORIG_SKIP_NDX   (origins[origin_no].skip_ndx)
#define ORIG_SKIP_STR   (origins[origin_no].skip_str)
#define ORIG_NAME(num)  (origins[origin_no].name[num])
#define ORIG_UNAME(num) (origins[origin_no].uname[num])
#define ORIG_WIDTH(num) (origins[origin_no].width[num])
#define ORIG_SKIPNDX_LEN  ARRAY_LEN(origins[origin_no].skip_ndx)
#define ORIG_SKIPSTR_LEN  ARRAY_LEN(origins[origin_no].skip_str)

static int ipinfo_no[II_REC_ARR_LEN] = {-1}; // the longest list: #8 getcitydetails.geobytes.com

enum { IPAPI_STATUS_NDX = 1, IPAPI_QUERYIP_NDX = 14};

static origin_t origins[] = {
// Abbreviations: CC - Country Code, RC - Region Code, MC - Metro Code, Org - Organization, TZ - TimeZone
// 1
  { .host  = "origin.asn.cymru.com", .host6 = "origin6.asn.cymru.com",
    .name  = {_II_ASN_STR, _II_ROUTE_STR, _II_CC_STR, _II_REG_STR, _II_ALLOC_STR},
    .asnth = 0,
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
    .name   = {_II_ROUTE_STR, _II_ORIGIN_STR, _II_DESC_STR, _II_CC_STR},
    .asnth  = 1,
    .sep    = 0,
    .type   = OT_WHOIS,
    .prefix = "-m ",
  },
// 3
  { .host     = "peer.asn.shadowserver.org",
    .name     = {_II_ASPATH_STR, _II_ASN_STR, _II_ROUTE_STR, /*_II_ASNAME_STR,*/ _II_CC_STR, _II_ORG_STR},
    .asnth    = 1,
    .sep      = VSLASH,
    .skip_ndx = {4},
  },
// 4
  { .host  = "origin.asn.spameatingmonkey.net",
    .name  = {_II_ROUTE_STR, _II_ASN_STR, _II_ORG_STR, _II_ALLOC_STR, _II_CC_STR},
    .asnth = 1,
    .unkn  = "Unknown",
    .sep   = VSLASH,
  },
// 5
  { .host  =
#ifdef ENABLE_DNS
      "ip-api.com",
#else
      "208.95.112.1",
#endif
    .name     = {/*Status,*/ _II_CNAME_STR, _II_CC_STR, _II_RC_STR, _II_RNAME_STR, _II_CITY_STR, _II_ZIP_STR,
                 _II_LAT_STR, _II_LNG_STR, _II_TZ_STR, _II_ISP_STR, _II_ORG_STR, _II_ASNAME_STR /*,QueryIP*/},
    .asnth    = 11,
    .sep      = COMMA,
    .type     = OT_HTTP,
    .skip_ndx = {IPAPI_STATUS_NDX, IPAPI_QUERYIP_NDX}, .prefix = "/csv/",
  },
// 6
  { .host  = "asn.routeviews.org",
    .name  = {_II_ASN_STR, _II_ROUTE_STR},
    .asnth = 0,
    .unkn  = "4294967295",
    .sep   = VSLASH,
    .comb_last_fields = '/', /* route / prefix */
  },
};

//

static bool str_in_skip_list(const char *str, uint len, const char* list[len]) NONNULL(1, 3);
static bool str_in_skip_list(const char *str, uint len, const char* list[len]) {
    for (uint i = 0; (i < len) && list[i]; i++)
        if (STR_EQ(str, list[i], NAMELEN))
            return true;
    return false;
}

static bool ndx_in_skip_list(int ndx, uint len, const int list[len]) NONNULL(3);
static bool ndx_in_skip_list(int ndx, uint len, const int list[len]) {
    for (uint i = 0; (i < len) && list[i]; i++)
        if ((ndx + 1) == list[i])
            return true;
    return false;
}

static int split_with_sep(uint len, char* list[len], char sep, char quote) NONNULL(2);
static int split_with_sep(uint len, char* list[len], char sep, char quote) {
  if (!*list)
    return 0;
  uint count = 1;
  bool inside = false;
  //
  for (char *ptr = *list, **next = list + 1; *ptr; ptr++) {
    if ((*ptr == sep) && !inside) {
      if (count >= len)
        break;
      count++;
      *ptr = 0;
      *next++ = ptr + 1;
    } else if (*ptr == quote)
      inside = !inside;
  }
  for (uint i = 0; (i < count) && list[i]; i++)
    list[i] = trim(list[i]);
  return (count > len) ? len : count;
}

static void unkn2norm(uint len, char* record[len]) NONNULL(2);
static void unkn2norm(uint len, char* record[len]) {
  if (ORIG_UNKN) { // change to common UNKN
    size_t lim = strnlen(ORIG_UNKN, NAMELEN);
    for (uint i = 0; (i < len) && record[i]; i++)
      if (STR_EQ(record[i], ORIG_UNKN, lim))
        record[i] = UNKN;
  }
}

static char** split_record(char *data, uint len, char* list[len]) NONNULL(1, 3);
static char** split_record(char *data, uint len, char* list[len]) {
  list[0] = data;
  split_with_sep(len, list, origins[origin_no].sep, '"');
  unkn2norm(len, list);
  return list;
}

static void readjust_nth_width(uint nth, int width) {
  if (ORIG_WIDTH(nth) < width) {
    ORIG_WIDTH(nth) = width;
    if (!ipinfo_rewidth)
        ipinfo_rewidth = true;
  }
}

static void adjust_width(uint len, ii_record_view_t record[len]) NONNULL(2);
static void adjust_width(uint len, ii_record_view_t record[len]) {
  for (uint i = 0; (i < len) && record[i].view; i++)
    readjust_nth_width(i, ustrnlen(record[i].view, NAMELEN));
}

static bool set_newrec(int at, int ndx, int j, char *dup, int sndx) {
  if (dup) {
    char **p = (sndx < 0) ? &II_VIEW_AT(at, ndx, j) : &II_SRC_AT(at, ndx, j, sndx);
    if (*p)
      free(*p);
    *p = dup;
  } else if (sndx < 0)
    WARN("no dup[%d:%d:%d]", at, ndx, j);
  else
    WARN("no dup[%d:%d:%d:%d]", at, ndx, j, sndx);
  return dup != NULL;
}

static inline int snprint_addmulti(uint len, char buff[len],
  const char *prev, const char *str, bool multi) NONNULL(2, 3, 4);
static inline int snprint_addmulti(uint len, char buff[len],
  const char *prev, const char *str, bool multi)
{
  return multi ?
    snprinte(buff, len, "%s, %s", prev, str) :
    snprinte(buff, len, "%s*", prev);
}

static void save_fields(int at, int ndx, uint rlen, char* record[rlen], bool add, uint srcndx) {
  unkn2norm(rlen, record);
  for (int i = 0; i < itemname_max; i++)
    if (!record[i])
      record[i] = UNKN;
  for (uint i = 0, j = 0; (i < rlen) && record[i]; i++) {
    if (!ndx_in_skip_list(i, ORIG_SKIPNDX_LEN, ORIG_SKIP_NDX)) {
      char *str = trim(record[i]);
      if (str && str[0] && !str_in_skip_list(str, ORIG_SKIPSTR_LEN, ORIG_SKIP_STR)) {
        char buff[NAMELEN] = {0};
        char *pview = buff, *view = II_VIEW_AT(at, ndx, j);
        int len = snprinte(buff, sizeof(buff), "%s", str);
        if (len > 0) {
          char mbuff[NAMELEN] = {0};
          if (view && add) {
            len = snprint_addmulti(sizeof(mbuff), mbuff, view, str, run_opts.multi);
            if (len > 0)
              pview = mbuff;
          }
          if (len > 0) {
            bool view_ok = set_newrec(at, ndx, j, strndup(pview, NAMELEN), -1);
            bool src_ok  = set_newrec(at, ndx, j, strndup(buff, sizeof(buff)), srcndx);
            if (!view_ok || !src_ok)
              break;
          }
        }
        //
        LOGMSG(" rec[%d, %d, %d, %d]: %s", at, ndx, j, srcndx, II_SRC_AT(at, ndx, j, srcndx));
        LOGMSG("view[%d, %d, %d]: %s", at, ndx, j, II_VIEW_AT(at, ndx, j));
        j++;
      }
    }
  }
}

// test out if sources are the same
static bool same_ii_src(int at, int ndx, int num, const char *first) NONNULL(4);
static bool same_ii_src(int at, int ndx, int num, const char *first) {
    bool same = true;
    for (uint i = 1; i < II_SRC_ARR_LEN; i++) {
      char *str = II_SRC_AT(at, ndx, num, i);
      if (str)
        same = STR_EQ(first, str, NAMELEN);
      if (!same || !str)
        break;
    }
    return same;
}

static void review_at(int at, int ndx) {
  for (uint i = 0; i < II_REC_ARR_LEN; i++) {
    const char *first  = II_SRC_AT(at, ndx, i, 0);
    if (!first)
      continue;
    bool fin  = true;
    bool same = same_ii_src(at, ndx, i, first);
    if (first) {
      char buff[NAMELEN] = {0};
      bool more = II_SRC_AT(at, ndx, i, 1) != NULL;
      int len = (more && !run_opts.multi && !same) ?
        snprinte(buff, sizeof(buff), "%s*", first) :
        snprinte(buff, sizeof(buff), "%s", first);
      if ((len > 0) && !set_newrec(at, ndx, i, strndup(buff, sizeof(buff)), -1))
        break;
      fin = !more || (more && !run_opts.multi) || same;
    }
    //
    if (!fin) {
      for (uint k = 1; k < II_SRC_ARR_LEN; k++) {
        char *str = II_SRC_AT(at, ndx, i, k);
        if (str) {
          char buff[NAMELEN] = {0};
          int len = snprinte(buff, sizeof(buff), "%s, %s", II_VIEW_AT(at, ndx, i), str);
          if ((len > 0) && !set_newrec(at, ndx, i, strndup(buff, sizeof(buff)), -1))
            break;
        }
      }
    }
    //
    const char *view = II_VIEW_AT(at, ndx, i);
    LOGMSG("view[%d, %d, %d]: %s", at, ndx, i, view);
    //
    int width = ustrnlen(view, NAMELEN);
    int uname = ustrnlen(ORIG_UNAME(i), NAMELEN);
    if (width < uname)
      width = uname;
    readjust_nth_width(i, width);
  }
}

static void reset_view(void) {
  memset(origins[origin_no].width, 0, sizeof(origins[origin_no].width)); // reset widths
  int max = net_max();
  for (int at = net_min(); at < max; at++)
    for (int ndx = 0; ndx < MAXPATH; ndx++)
      if (addr_exist(&IP_AT_NDX(at, ndx)))
        review_at(at, ndx);
}

#ifdef ENABLE_DNS
static inline void save_txt_prepare(char *txt, char comb, char delim) NONNULL(1);
static inline void save_txt_prepare(char *txt, char comb, char delim) {
  if (comb && delim) {
    char *found = strrchr(txt, delim);
    if (found)
        *found = comb;
  }
}

static void save_txt_answer(int at, int ndx, const char *answer, size_t alen) {
  char* copy = NULL;
  char* data[II_REC_ARR_LEN] = {0};
  size_t lim = (alen < NAMELEN) ? alen : NAMELEN;
  if (answer && strnlen(answer, lim)) {
    copy = strndup(answer, lim);
    if (!copy) {
      WARN("[%d:%d]: strndup()", at, ndx);
      return;
    }
    save_txt_prepare(copy, origins[origin_no].comb_last_fields, origins[origin_no].sep);
    split_record(copy, ARRAY_LEN(data), data);
  }
  save_fields(at, ndx, ARRAY_LEN(data), data, SETFIELDS, 0); // if data is empty, it's set as unknown
  if (copy)
    free(copy);
  adjust_width(II_REC_ARR_LEN, II_REC_ARR(at, ndx));
}
#endif

static void save_records(atndx_t id, uint rlen, char* record[rlen], bool add, uint sndx) {
  // save results of parsing
  save_fields(id.at, id.ndx, rlen, record, add, sndx);
  adjust_width(II_REC_ARR_LEN, II_REC_ARR(id.at, id.ndx));
}

static int trim_n_count_records(uint len, char* record[len]) {
  int count = 0;
  for (uint i = 0; (i < len) && record[i]; i++) {
    if (!ndx_in_skip_list(i, ORIG_SKIPNDX_LEN, ORIG_SKIP_NDX)) {
      record[i] = trim(record[i]);
      if (!str_in_skip_list(record[i], ORIG_SKIPSTR_LEN, ORIG_SKIP_STR))
        count++;
    }
  }
  return count;
}

static inline int parse_http_content_len(uint lines_no, char* lines[TCP_RESP_LINES],
	size_t recv_size, uint *cndx) {
  uint ndx = 0, len = 0; // content index in tcp response and its length
  uint min = lines_no < TCP_RESP_LINES ? lines_no : TCP_RESP_LINES;
  const char cntx_len_tag[] = "Content-Length:";
  for (uint i = 0; i < min; i++) {
    char* pair[2] = {lines[i], NULL};
    if (split_with_sep(ARRAY_LEN(pair), pair, ' ', 0) == ARRAY_LEN(pair)
      && STR_EQ(cntx_len_tag, pair[0], sizeof(cntx_len_tag))
      && pair[1])
    {
        errno = 0;
        long n = str2l(pair[1]);
        if (errno)
          errno = 0;
        else if ((0 < n) && (n <= INT_MAX))
          len = n;
    }
    if (lines[i][0]) // skip header lines
      continue;
    if ((i + 1) < lines_no)
      ndx = i + 1;
    break;
  }
  if (ndx && (len > 0) && (len < recv_size))
    *(lines[ndx] + len) = 0;
  else
    len = ustrnlen(lines[ndx], NAMELEN);
  if (cndx) *cndx = ndx;
  return (len < NETDATA_MAXSIZE) ? len : NETDATA_MAXSIZE;
}

static void parse_http(atndx_t id, int len, char txt[len]) {
  /*summ*/ ipinfo_replies[0]++; ipinfo_replies[1]++;
  char* list[II_REC_ARR_LEN] = {0};
  const char http1_1[] = "HTTP/1.1";
  //
  int got = -1;
  char *ptr =
#ifdef HAVE_MEMMEM
    memmem(txt, len, http1_1, sizeof(http1_1) - 1);
#else
    strstr(txt, http1_1);
#endif
  if (ptr) {
    ptr += sizeof(http1_1); // i.e. beyond 'HTTP/1.1 '
    char okay[] = "200 OK";
    int olen = sizeof(okay) - 1;
    if (STR_NEQ(ptr, okay, olen)) // HTTP OK, or not
      LOGMSG("not OK: %.*s", olen, ptr);
    else {
      char* lines[TCP_RESP_LINES] = {txt};
      uint lines_no = split_with_sep(ARRAY_LEN(lines), lines, '\n', 0);
      if (lines_no < 4) // HEADER + NL + NL + DATA
        LOGMSG("No data after header (got %d lines only)", lines_no);
      else {
        uint cndx = 0, clen = parse_http_content_len(lines_no, lines, len, &cndx);
        // combine into one line
        char context[clen + 1];
        memset(context, 0, sizeof(context));
        for (uint i = cndx, len = 0; (i < lines_no) && (len < clen); i++) {
          int inc = snprinte(context + len, clen - len, "%s", lines[i]);
          if (inc < 0)
            break;
          len += inc;
        }
        LOGMSG("context(%.*s)", clen, context);
        //
        split_record(context, ARRAY_LEN(list), list);
        got = trim_n_count_records(ARRAY_LEN(list), list);
        if (got == itemname_max) { // success
          save_records(id, ARRAY_LEN(list), list, SETFIELDS, 0);
          return;
        }
      }
    }
  }
  // fail
  LOGMSG("Expected %d records, got %d", itemname_max, got < 0 ? 0 : got);
  memset(list, 0, sizeof(list)); // as unknown
  save_records(id, ARRAY_LEN(list), list, SETFIELDS, 0);
}

static void parse_whois_tagvalue(char* line, uint rlen, char* record[rlen]) {
  char* tagvalue[2] = {line, NULL};
  if (split_with_sep(ARRAY_LEN(tagvalue), tagvalue, ':', 0) != ARRAY_LEN(tagvalue))
    return;
  if (!tagvalue[0] || !tagvalue[1])
    return;
  LOGMSG("whois-in: %s=\"%s\"", tagvalue[0], tagvalue[1]);
  if (af == AF_INET6) { // trim trailing '6' to test IPv6 fields as well
    size_t end = strnlen(tagvalue[0], NAMELEN) - 1;
    if ((end > 0) && (tagvalue[0][end] == '6'))
      tagvalue[0][end] = 0;
  }
  if (rlen > ARRAY_LEN(origins[0].name))
    rlen = ARRAY_LEN(origins[0].name);
  for (uint i = 0; (i < rlen) && ORIG_NAME(i); i++) {
    if (!strcasecmp(ORIG_NAME(i), tagvalue[0])) {
      record[i] = tagvalue[1];
      if (i == WHOIS_LAST_NDX) { // split the last item (description, country)
        char *cc = record[i] ? strrchr(record[i], COMMA) : NULL;
        if (cc) {
          uint ic = i + 1;
          if (ic < rlen) {
            *cc++ = 0;
            record[ic] = cc;
            LOGMSG("whois-out: %s=\"%s\"", ORIG_NAME(ic), record[ic]);
          }
        }
      }
      LOGMSG("whois-out: %s=\"%s\"", tagvalue[0], tagvalue[1]);
      break;
    }
  }
}

static void split_by_empty_lines(int len, char txt[len], uint n, char* arr[n]) {
  uint ndx = 0;
  arr[ndx] = txt;
  while (txt && (len > 0) && (ndx < n)) {
    char *mark = memchr(txt, '\n', len); // 1st NL
    if (!mark)
      break;
    len -= ++mark - txt;
    txt = mark;
    if (txt && (*txt == '\n')) { // 2nd NL
      len--;
      *txt++ = 0;
      if (!*txt)
        break;
      arr[++ndx] = txt;
    }
  }
}

static int skip_whois_nodata(uint len, char* lines[len]) NONNULL(2);
static int skip_whois_nodata(uint len, char* lines[len]) {
  char* data[len];
  memset(data, 0, sizeof(data));
  uint count = 0;
  for (uint i = 0; i < len; i++)
    if (lines[i] && lines[i][0]) {
      char *s = trim(lines[i]);
      if (s && s[0] && s[0] != WHOIS_COMMENT)
        data[count++] = s;
    }
  memcpy(lines, data, sizeof(data));
  return count;
}

static void parse_whois(atndx_t id, uint len, char txt[len]) {
  /*summ*/ ipinfo_replies[0]++; ipinfo_replies[2]++;
  char* msrc[II_SRC_ARR_LEN + 1] = {0};
  split_by_empty_lines(len, txt, ARRAY_LEN(msrc) - 1, msrc);
  bool op = SETFIELDS;
  uint srcno = 0;
  for (char **src = msrc; *src; src++) {
    char* lines[TCP_RESP_LINES] = {*src};
    uint count = split_with_sep(ARRAY_LEN(lines), lines, '\n', 0);
    if (count) {
      char* record[II_REC_ARR_LEN] = {0};
      uint datacnt = skip_whois_nodata(count, lines);
      if (!datacnt) // empty segment
        LOGMSG("%s", "Skip empty segment");
      else {
        if (datacnt > ARRAY_LEN(lines))
          datacnt = ARRAY_LEN(lines);
        for (uint i = 0; (i < datacnt) && lines[i]; i++)
          parse_whois_tagvalue(lines[i], ARRAY_LEN(record), record);
        save_records(id, ARRAY_LEN(record), record, op, srcno++);
        if (op == SETFIELDS)
          op = ADDFIELDS;
      }
    }
  }
  if (op == ADDFIELDS) // i.e. some records are saved
    reset_view();
  else {      // otherwise save empty data as unknown
    char* record[II_REC_ARR_LEN] = {0};
    save_records(id, ARRAY_LEN(record), record, op, 0);
  }
}

static void close_ipitseq(int seq) {
  if (ipitseq) {
    int sock = ipitseq[seq].sock;
    if (ipitseq[seq].sock >= 0) {
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
}

void ipinfo_parse(int sock, int seq) { // except dns, dns.ack in dns.c
  char data[NETDATA_MAXSIZE + 1] = {0};
  seq %= MAXSEQ;
  ssize_t received = recv(sock, data, sizeof(data) - 1, 0);
  if (received > 0) {
    atndx_t id = { .at = seq / MAXPATH, .ndx = seq % MAXPATH };
    switch ORIG_TYPE {
      case OT_HTTP:
        LOGMSG( "HTTP: got[%zd]: \"%.*s\"", received, (int)received, data);
        parse_http(id, received, data);
        return;
      case OT_WHOIS:
        LOGMSG("WHOIS: got[%zd]: \"%.*s\"", received, (int)received, data);
        parse_whois(id, received, data);
        return;
      default: break;
    }
  } else if (received < 0)
    WARN("seq=%d recv(sock=%d)", seq, sock);
  close_ipitseq(seq);
}


static int create_tcpsock(int seq) {
  uint16_t port = (ORIG_TYPE == OT_WHOIS) ? WHOIS_PORT : HTTP_PORT;
  char srv[8] = {0};
  snprinte(srv, sizeof(srv), "%u", port);
  LOGMSG("%s:%s", ORIG_HOST, srv);
  if (!srv[0]) return -1;
  struct addrinfo *rp = NULL, hints = {
    .ai_family = af,
    .ai_socktype = SOCK_STREAM,
    .ai_protocol = IPPROTO_TCP };
  int ecode = getaddrinfo(ORIG_HOST, srv, &hints, &rp);
  if (ecode || !rp)
    LOGRET_RC(-1, "getaddrinfo(%s): %s", ORIG_HOST, gai_strerror(ecode));
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
  if (ORIG_TYPE == OT_WHOIS)
    snprinte(buf, sizeof(buf), "%s\r\n", q);
  else
    snprinte(buf, sizeof(buf), HTTP_GET, q, ORIG_HOST, PACKAGE_NAME);
  size_t len = strnlen(buf, sizeof(buf));
  if (!len) {
    errno = EINVAL;
    return -1;
  }
  int rc = send(sock, buf, len, 0);
  if (rc >= 0) {
    /*summ*/ ipinfo_queries[0]++; (ORIG_TYPE == OT_HTTP) ? ipinfo_queries[1]++ : ipinfo_queries[2]++;
  }
  LOGMSG("[orig=%d sock=%d] q=\"%s\" rc=%d ts=%lld", origin_no, sock, q, rc, (long long)time(NULL));
  return rc;
}

static const char* make_tcp_qstr(int at, int ndx, size_t size, char query[size]) NONNULL(4);
static const char* make_tcp_qstr(int at, int ndx, size_t size, char query[size]) {
  char str[MAX_ADDRSTRLEN] = {0};
  const char *addr = inet_ntop(af, &IP_AT_NDX(at, ndx), str, sizeof(str));
  if (addr) {
    snprinte(query, size, "%s%s", origins[origin_no].prefix, addr);
    if (query[0])
      return query;
  }
  return NULL;
}

void ipinfo_seq_ready(int seq) {
  seq %= MAXSEQ;
  int at = seq / MAXPATH, ndx = seq % MAXPATH;
  LOGMSG("seq=%d at=%d ndx=%d", seq, at, ndx);
  ipitseq[seq].state = TSEQ_READY;
  QTXT_TS_AT_NDX(at, ndx) = time(NULL); // save send-time
  char query[NAMELEN] = {0};
  const char *q = make_tcp_qstr(at, ndx, sizeof(query), query);
  if (q)
    send_tcp_query(ipitseq[seq].sock, q);
}

static int ipinfo_lookup(int at, int ndx, const char *qstr) {
  if (!(run_opts.asn || run_opts.ipinfo)) // not enabled
    return -1;
  if (!addr_exist(&IP_AT_NDX(at, ndx))) // on the off chance
    return -1;
  if (II_VIEW_AT(at, ndx, 0)) // already known
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
    (ORIG_TYPE == OT_DNS) ? dns_send_query(at, ndx, qstr, ns_t_txt) :
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
  if (II_VIEW_AT(at, ndx, item_no)) // already known
    return II_VIEW_AT(at, ndx, item_no);
#ifdef ENABLE_IPV6
  if (af == AF_INET6) {
    if (!origins[origin_no].host6) return NULL;
  } else
#endif
  { if (!ORIG_HOST) return NULL; }
  t_ipaddr *ipaddr = &IP_AT_NDX(at, ndx);
  char query[NAMELEN] = {0};
  switch (ORIG_TYPE) {
    case OT_HTTP:
    case OT_WHOIS: {
      const char *q = make_tcp_qstr(at, ndx, sizeof(query), query);
      if (q)
        ipinfo_lookup(at, ndx, q);
    } break;
#ifdef ENABLE_DNS
    default: // dns
      ip2arpa(sizeof(query), query, ipaddr, ORIG_HOST, origins[origin_no].host6);
      if (query[0])
        ipinfo_lookup(at, ndx, query);
    break;
#endif
  }
  return NULL;
}

int ipinfo_width(void) {
  int width = 0;
  for (uint i = 0; (i < ARRAY_LEN(ipinfo_no))
      && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
      && (width < NAMELEN); i++)
    width += ORIG_WIDTH(ipinfo_no[i]) + 1;
  return width;
}

//
typedef int (*str_filler_fn)(uint size, char buff[size], const char *str, int num, char q) NONNULL(2);
//
static int str_filler(uint size, char buff[size], const char *str, int div, char q) NONNULL(2);
static int str_filler(uint size, char buff[size], const char *str, int div, char q) {
  if (!str)
    str = UNKN;
  return (div > 0)
    ? (q ?
       snprinte(buff, size, "%c%c%s%c", div, q, str, q) :
       snprinte(buff, size, "%c%s",     div,    str))
    : (q ?
       snprinte(buff, size, "%c%s%c",        q, str, q) :
       snprinte(buff, size, "%s",               str));
}
// 'div'-separated output
void ipinfo_head_div(size_t size, char buff[size], char div, char q) { // NONNULL(2)
  if (run_opts.asn)
    str_filler(size, buff, ORIG_UNAME(origins[origin_no].asnth), 0, q);
  else
    for (uint i = 0, len = 0; (i < ARRAY_LEN(ipinfo_no))
         && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
         && ORIG_UNAME(ipinfo_no[i]) && (size > len); i++)
  {
    int inc = str_filler(size - len, buff + len, ORIG_UNAME(ipinfo_no[i]), i ? div : 0, q);
    if (inc < 0)
      break;
    len += inc;
  }
}
//
static int ipinfo_head_fix_nth(size_t size, char buff[size], int iino) NONNULL(2);
static int ipinfo_head_fix_nth(size_t size, char buff[size], int iino) {
  int gap = ORIG_WIDTH(iino) - ustrnlen(ORIG_UNAME(iino), NAMELEN);
  if (gap < 0)
    gap = 0;
  return snprinte(buff, size, "%s%*s", ORIG_UNAME(iino), gap + 1, "");
}
// fixed width output
void ipinfo_head_fix(size_t size, char buff[size]) { // NONNULL(2)
  if (run_opts.asn)
    ipinfo_head_fix_nth(size, buff, origins[origin_no].asnth);
  else
    for (uint i = 0, len = 0; (i < ARRAY_LEN(ipinfo_no))
         && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
         && ORIG_UNAME(ipinfo_no[i]) && (size > len); i++)
  {
    int inc = ipinfo_head_fix_nth(size - len, buff + len, ipinfo_no[i]);
    if (inc < 0)
      break;
    len += inc;
  }
}
//
static int fmt_filler(uint size, char buff[size], const char *str, int width, char q UNUSED) NONNULL(2);
static int fmt_filler(uint size, char buff[size], const char *str, int width, char q UNUSED) {
  if (!str)
    str = UNKN;
  return (width > 0) ?
    snprinte(buff, size, "%-*s ", width, str) :
    snprinte(buff, size,   "%s ",        str);
}
//
static inline int ipinfo_data_div_nth(size_t size, char buff[size], int at, int ndx,
  uint iino, char div, int nth, str_filler_fn filler, char q) NONNULL(2, 8);
static inline int ipinfo_data_div_nth(size_t size, char buff[size], int at, int ndx,
  uint iino, char div, int nth, str_filler_fn filler, char q)
{
  return filler(size, buff,
    addr_exist(&IP_AT_NDX(at, ndx)) ? get_ipinfo(at, ndx, iino) : NULL,
    div ? (nth ? div : 0) : ORIG_WIDTH(iino),
    q);
}
// formatted output
void ipinfo_data_div(size_t size, char buff[size], int at, int ndx, char div, char q) { // NONNULL(2)
  str_filler_fn filler = div ? str_filler : fmt_filler;
  if (run_opts.asn)
    ipinfo_data_div_nth(size, buff, at, ndx, origins[origin_no].asnth, div, 0, filler, q);
  else
    for (uint i = 0, len = 0; (i < ARRAY_LEN(ipinfo_no))
         && (ipinfo_no[i] >= 0) && (ipinfo_no[i] < itemname_max)
         && (size > len); i++)
  {
    int inc = ipinfo_data_div_nth(size - len, buff + len, at, ndx, ipinfo_no[i], div, i, filler, q);
    if (inc < 0)
      break;
    len += inc;
  }
}
//
inline void ipinfo_data_fix(size_t size, char buff[size], int at, int ndx) { // NONNULL(2)
  ipinfo_data_div(size, buff, at, ndx, 0, 0); }
//

static bool alloc_ipitseq(void) {
  if (!ipitseq) {
    size_t size = sizeof(ipitseq_t) * MAXHOST * MAXPATH;
    ipitseq = malloc(size);
    if (ipitseq) {
      memset(ipitseq, -1, size);
      LOGMSG("allocated %zd bytes for tcp-sockets", size);
    } else
      WARN("tcpseq malloc(%zd)", size);
  }
  return ipitseq != NULL;
}

#ifdef ENABLE_DNS
#define DNS_OPEN dns_open()
#else
#define DNS_OPEN false
#endif

static bool ipinfo_open(void) {
  ipinfo_ready = (ORIG_TYPE == OT_DNS) ? DNS_OPEN :
    (ipitseq ? true : alloc_ipitseq()); // http or whois
#ifdef ENABLE_DNS
  if (!dns_txt_handler) // use-note: only in ipinfo so far
    dns_txt_handler = save_txt_answer;
#endif
  LOGMSG("%s", ipinfo_ready ? "ok" : "failed");
  return ipinfo_ready;
}

void ipinfo_close(void) {
  if (ipitseq) {
    for (int i = 0; i < MAXHOST * MAXPATH; i++)
      close_ipitseq(i);
    free(ipitseq);
    ipitseq = NULL;
    LOGMSG("%s", "free tcp-sockets memory");
  }
  if (ipinfo_ready)
    ipinfo_ready = false;
#ifdef ENABLE_DNS
  if (ORIG_TYPE == OT_DNS)
    dns_close();
#endif
  LOGMSG("%s", "ok");
}

#define LIM_CHARS 20

bool ipinfo_init(const char *arg) {
  if (!arg)
    arg = ASLOOKUP_DEFAULT;
  char* args[II_REC_ARR_LEN + 1] = {strdup(arg)};
  if (!args[0]) {
    WARN("strdup(%s)", arg);
    return false;
  }
  split_with_sep(ARRAY_LEN(args) - 1, args, COMMA, 0);
  if (!args[0]) {
    errno = EINVAL;
    WARN("split_with_sep(%s)", arg);
    return false;
  }
  //
  int omax = ARRAY_LEN(origins);
  int org = -1;
  errno = 0;
  if (*args[0]) {
    long n = str2l(args[0]);
    if (!errno && (0 <= n) && (n <= omax))
      org = n;
  }
  if ((org > 0) && (org <= omax)) {
    origin_no = org - 1;
    ipinfo_tcpmode = (ORIG_TYPE != OT_DNS);
  } else {
    if (errno)
      warn("%s: -L%.*s...", IPINFO_STR, LIM_CHARS, args[0]);
    else {
      errno = ERANGE;
      warn("%s %s[1..%d]: %.*s", IPINFO_STR, RANGE_STR, omax, LIM_CHARS, args[0]);
    }
    errno = 0;
    free(args[0]);
    return false;
  }
  itemname_max = 0;
  while (ORIG_NAME(itemname_max))
    itemname_max++;
  //
  uint j = 0;
  for (uint i = 1; args[i] && (i < ARRAY_LEN(args)) && (j < ARRAY_LEN(args) - 1); i++) {
    if (*args[i]) {
      errno = 0; long n = str2l(args[i]);
      if (errno) {
        warn("%s: -L%u [%u]=%.*s", IPINFO_STR, org, i + 1, LIM_CHARS, args[i]);
        errno = 0;
      } else if ((0 < n) && (n <= itemname_max))
        ipinfo_no[j++] = n - 1;
      else
        warnx("%s: -L%u [%u]=%.*s: %s", IPINFO_STR, org, i + 1, LIM_CHARS, args[i], SKIPPED_STR);
    } else
      warnx("%s: -L%u [%u]: %s", IPINFO_STR, org, i + 1, NONE_STR);
  }
  for (uint i = j; i < ARRAY_LEN(ipinfo_no); i++)
    ipinfo_no[i] = -1;
  if (ipinfo_no[0] < 0)
    ipinfo_no[0] = 0;
  //
  free(args[0]);
  //
  uint imax = ARRAY_LEN(origins[0].name);
  if (ARRAY_LEN(origins[0].width) < imax)
    imax = ARRAY_LEN(origins[0].width);
  for (uint i = 0; (i < imax) && ORIG_NAME(i); i++) {
    ORIG_UNAME(i) = _(ORIG_NAME(i));
    if (!ORIG_UNAME(i))
      ORIG_UNAME(i) = ORIG_NAME(i);
    readjust_nth_width(i, ustrnlen(ORIG_UNAME(i), NAMELEN));
  }
  //
  LOGMSG("Source: %s%s%s", ORIG_HOST, origins[origin_no].host6 ? ", " : "",
    origins[origin_no].host6 ? origins[origin_no].host6 : "");
  return true;
}

#undef MAXFIELDCHARS


bool ipinfo_action(key_action_t action) {
  if ((ipinfo_no[0] < 0) // not at start, set default
    && !ipinfo_init(NULL))
      return false;
  if (!ipinfo_ready && !ipinfo_open())
    return false;
  switch (action) {
    case ActionASN:  // `l'
      run_opts.asn = !run_opts.asn;
      if (run_opts.ipinfo)
        run_opts.ipinfo = false;
      break;
    case ActionII: { // `L'
      static bool postponed_L;
      if (!run_opts.ipinfo)
        run_opts.ipinfo = true;
      if (run_opts.asn)
        run_opts.asn = false;
      if (postponed_L)
        postponed_L = false;
      else {
        for (uint i = 0; (i < ARRAY_LEN(ipinfo_no)) && (ipinfo_no[i] >= 0); i++) {
          ipinfo_no[i]++;
          if (ipinfo_no[i] >= itemname_max)
            ipinfo_no[i] = 0;
        }
        if (!ipinfo_no[0]) {
          postponed_L = true;
          run_opts.ipinfo = false;
        }
      }
    } break;
    case ActionMultiII: // `y'
      run_opts.multi = !run_opts.multi;
      reset_view();
      break;
    default: break;
  }
  return true;
}

static void query_iiaddr(int at, int ndx) {
  if (run_opts.asn)
    get_ipinfo(at, ndx, origins[origin_no].asnth);
  else
    for (uint i = 0; (i < ARRAY_LEN(ipinfo_no)) && (ipinfo_no[i] >= 0); i++)
      get_ipinfo(at, ndx, ipinfo_no[i]);
}

void query_ipinfo(void) {
  if (ipinfo_ready) {
    int max = net_max();
    for (int at = net_min(); at < max; at++) {
      if (addr_exist(&CURRENT_IP(at))) {
        query_iiaddr(at, host[at].current);
        for (int i = 0; i < MAXPATH; i++) {
          if ((i != host[at].current) // already queried
              && addr_exist(&IP_AT_NDX(at, i)))
            query_iiaddr(at, i);
        }
      }
    }
  }
}

