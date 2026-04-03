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
#include <assert.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "common.h"
#include "nls.h"

#include "aux.h"
#include "report.h"
#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#ifndef MAXDNAME
#define MAXDNAME 1025
#endif

enum INDENTS_N_DIVIDERS {
  IND_REP     = 4,
#ifdef OUTPUT_FORMAT_CSV
  DIV_CSV     = ';',
#endif
#ifdef OUTPUT_FORMAT_JSON
  DIV_JSON    = ',',
  IND_JSON    = 4,
#endif
#ifdef OUTPUT_FORMAT_TOON
  DIV_TOON    = ',',
  IND_TOON    = 2,
#endif
#ifdef OUTPUT_FORMAT_XML
  DIV_XML     = ',',
  IND_XML     = 2,
#endif
};

#define QUOTE(str, delim) strchr((str), (delim)) ? "\"" : "";

static time_t started_at;
void report_started_at(void) { started_at = time(NULL); }

#if (__GNUC__ >= 8) || (__clang_major__ >= 6) || (__STDC_VERSION__ >= 202311L)
#define PRINT_DATETIME(fmt, ...) do {                           \
  char str[64] = {0};                                           \
  const char *date = datetime(started_at, str, sizeof(str));    \
  if (date && date[0]) printf((fmt) __VA_OPT__(,) __VA_ARGS__); \
} while(0)
#else
#define PRINT_DATETIME(fmt, ...) do {                           \
  char str[64] = {0};                                           \
  const char *date = datetime(started_at, str, sizeof(str));    \
  if (date && date[0]) printf((fmt), ##__VA_ARGS__);            \
} while(0)
#endif

static inline void print_str_width(const char str[], int width) NONNULL(1);
static inline void print_str_width(const char str[], int width) {
  if (width < 0) printf("%s", str);
  else printf("%-*s", width, str);
}

static void print_nameaddr(int at, int ndx, int width) {
  if (!width) return;
  t_ipaddr *ipaddr = &IP_AT_NDX(at, ndx);
  if (addr_exist(ipaddr)) {
#ifdef ENABLE_DNS
    const char *name = run_opts.dns ? dns_ptr_cache(at, ndx) : NULL;
    if (name) {
      if (run_opts.both) {
        if (width > 0) {
          char buff[MAXDNAME] = {0};
          snprinte(buff, sizeof(buff), "%s (%s)", name, strlongip(ipaddr));
          print_str_width(buff, width);
        } else
          printf("%s (%s)", name, strlongip(ipaddr));
      } else print_str_width(name, width);
    } else
#endif
      print_str_width(strlongip(ipaddr), width);
  } else
    print_str_width(UNKN_ITEM, width);
}

static int snprint_addr(char buf[], size_t size, uint at, uint ndx) {
  if (!buf || !size) return 0;
  int len = 0;
  t_ipaddr *ipaddr = &IP_AT_NDX(at, ndx);
  if (addr_exist(ipaddr)) {
#ifdef ENABLE_DNS
    const char *name = run_opts.dns ? dns_ptr_cache(at, ndx) : NULL;
    if (name) {
      len = run_opts.both ?
        snprinte(buf, size, "%s (%s)", name, strlongip(ipaddr)) :
        snprinte(buf, size, "%s",      name);
    } else
#endif
      len = snprinte(buf, size, "%s", strlongip(ipaddr));
  } else
    len = snprinte(buf, size, "%s", UNKN_ITEM);
  return (len < 0) ? 0 : len;
}

#ifdef WITH_MPLS
static void print_mpls(const mpls_data_t *mpls) {
  for (int i = 0; i < mpls->n; i++)
    printf("%s\n", mpls2str(&mpls->label[i], 4));
}
#endif

static int longest_hopname(int longest) {
  char buff[MAXDNAME] = {0};
  int nmax = net_max();
  for (int at = net_min(); at < nmax; at++) {
    for (uint i = 0; i < MAXPATH; i++) {
      int len = snprint_addr(buff, sizeof(buff), at, i);
      if (len > longest)
        longest = len;
    }
  }
  return longest;
}

#ifdef ENABLE_DNS
void backresolv_lookups(void) {
  if (!run_opts.dns) return;
  int max = net_max();
  for (int at = net_min(); at < max; at++) if (addr_exist(&CURRENT_IP(at))) {
    dns_ptr_lookup(at, host[at].current);
    for (int ndx = 0; ndx < MAXPATH; ndx++) { // multipath
      if (ndx == host[at].current) continue;
      if (!addr_exist(&IP_AT_NDX(at, ndx))) break;
      dns_ptr_lookup(at, ndx);
    }
  }
}
#endif

#ifdef WITH_IPINFO
static void report_info(int infolen, const char info[]) NONNULL(2);
static void report_info(int infolen, const char info[]) {
  if (!infolen) return;
  if (info[0]) { // note: utf8 length
    int len = infolen - ustrnlen(info, infolen) + 1;
    printf("%s%*s", info, (len < 0) ? 0 : len, "");
  } else
    printf("%*s", infolen + 1, "");
}
#define REPORT_INFO(a, b) report_info(a, b)
#else
#define REPORT_INFO(a, b) NOOP
#endif

static void report_headstat(int at UNUSED, const t_stat *stat) {
  if (stat->name)
    printf("%*s%s", (stat->min > stat->len) ? (stat->min - stat->len) : 1, "", stat->name);
  else
    printf("%*s", stat->min, "");
}

static void report_print_header(int hostlen, int infolen) {
  printf("%*s", IND_REP, "");
  // left
  { char info[NAMELEN] = {0};
    ipinfo_head_fix(info, sizeof(info));
    REPORT_INFO(infolen, info); }
  { printf("%s", HOST_STR);
    int len = hostlen - ustrnlen(HOST_STR, hostlen);
    if (len > 0) printf("%*s", len, ""); }
  // right
  foreach_stat(0, report_headstat, '\n');
}

static void report_bodystat(int at, const t_stat *stat) NONNULL(2);
static void report_bodystat(int at, const t_stat *stat) {
  const char *str = net_elem(at, stat->key);
  if (str) {
    uint len = strnlen(str, stat->min);
    printf("%*s%s", (stat->min > len) ? (stat->min - len) : 1, "", str);
  } else
    printf("%*s", stat->min, "");
}

static void report_print_body(int at, const char *fmt, int hostlen, int infolen) {
  // body: left
  if (fmt) printf(fmt, at + 1);
  { char info[NAMELEN] = {0};
    ipinfo_data_fix(info, sizeof(info), at, host[at].current);
    REPORT_INFO(infolen, info); }
  print_nameaddr(at, host[at].current, hostlen);
  // body: right
  foreach_stat(at, report_bodystat, '\n');
#ifdef WITH_MPLS
  if (run_opts.mpls) print_mpls(&CURRENT_MPLS(at));
#endif
}

static void report_print_rest(int at, int hostlen, int infolen) {
  for (int i = 0; i < MAXPATH; i++) {
    if (i == host[at].current)
      continue; // because already printed
    if (!addr_exist(&IP_AT_NDX(at, i)))
      break; // done
    printf("%*s", IND_REP, "");
    { char info[NAMELEN] = {0};
      ipinfo_data_fix(info, sizeof(info), at, i);
      REPORT_INFO(infolen, info); }
    print_nameaddr(at, i, hostlen);
    putchar('\n');
#ifdef WITH_MPLS
    if (run_opts.mpls)
      print_mpls(&MPLS_AT_NDX(at, i));
#endif
  }
}

void report_close(bool next, bool with_header) {
  if (next) printf("\n");
  if (with_header) {
    PRINT_DATETIME("[%s] ", date);
    printf("%s: %s %s %s\n", srchost, PACKAGE_NAME, mtr_args, dsthost);
  }
  int hostlen = longest_hopname(ustrnlen(HOST_STR, MAXDNAME)) + 1;
  int infolen =
#ifdef WITH_IPINFO
    ipinfo_ready() ? ipinfo_width() :
#endif
    0;
  report_print_header(hostlen, infolen);
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    report_print_body(at, AT_FMT " ", hostlen, infolen);
    report_print_rest(at, hostlen, infolen); // multipath, mpls, etc.
  }
  if (tgterr_txt[0])
    printf("%s: %s\n", _(ERROR_STR), tgterr_txt);
}


#ifdef OUTPUT_FORMAT_XML

void xml_head(void) {
  printf("<?xml version=\"1.0\"?>\n");
  printf("<MTR SRC=\"%s\"", srchost);
  PRINT_DATETIME(" DATETIME=\"%s\"", date);
  if (mtr_args[0])
    printf(" ARGS=\"%s\"", mtr_args);
  printf(">\n");
}

void xml_tail(void) { printf("</MTR>\n"); }

static void xml_statline(int at, const t_stat *stat) {
  const char *str = net_elem(at, stat->key);
  if (str)
    printf("%*s<%s>%s</%s>\n", IND_XML * 3, "", stat->name, str, stat->name);
}

void xml_close(void) {
  printf("%*s<DST HOST=\"%s\">\n", IND_XML, "", dsthost);
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    printf("%*s<HOP TTL=\"%d\" HOST=\"", IND_XML * 2, "", at + 1);
    print_nameaddr(at, host[at].current, -1);
    printf("%s", "\">\n");
    foreach_stat(at, xml_statline, 0);
#ifdef WITH_IPINFO
    if (ipinfo_ready()) {
      char info[NAMELEN] = {0};
      ipinfo_data_div(info, sizeof(info), at, host[at].current, DIV_XML);
      if (info[0])
        printf("%*s<%s>[%s]</%s>\n", IND_XML * 3, "", IPINFO_STR, info, IPINFO_STR);
    }
#endif
    printf("%*s</HOP>\n", IND_XML * 2, "");
  }
  if (tgterr_txt[0])
    printf("%*s<ERROR>%s</ERROR>\n", IND_XML * 2, "", tgterr_txt);
  printf("%*s</DST>\n", IND_XML, "");
}
#endif


#ifdef OUTPUT_FORMAT_JSON

void json_head(void) {
  printf("{\"%s\":\"%s\"", SOURCE_STR, srchost);
  PRINT_DATETIME("%c\n\"%s\":\"%s\"", DIV_JSON, _(DATETIME_STR), date);
  if (mtr_optc > 0) {
    printf("%c\n\"%s\":[", DIV_JSON, ARGS_STR);
    for (uint i = 0; i < mtr_optc; i++) {
      if (i) putchar(DIV_JSON);
      printf("\"%s\"", mtr_optv[i]);
    }
    putchar(']');
  }
  printf("%c\n\"%s\":[", DIV_JSON, TARGETS_STR);
}
void json_tail(void) { printf("\n]}\n"); }

static void json_statline(int at, const t_stat *stat) {
  const char *elem = net_elem(at, stat->key);
  if (!elem) return;
  int len = strnlen(elem, NETELEM_MAXLEN);
  if (len > 0) {
    const char *q = QUOTE(elem, DIV_JSON);
    if (elem[len - 1] == '%') // print '%' with name
      printf("%c\"%s%%\":%s%.*s%s", DIV_JSON, stat->name, q, len - 1, elem, q);
    else
      printf("%c\"%s\":%s%s%s",     DIV_JSON, stat->name, q,          elem, q);
  }
}

void json_close(bool next) {
  if (next) printf(",");
  printf("\n%*s{\"%s\":\"%s\"", IND_JSON, "", _(TARGET_STR), dsthost);
  printf("%c\"%s\":[", DIV_JSON, _(DATA_STR));
  int min = net_min(), max = net_max();
  for (int at = min; at < max; at++) {
    printf((at == min) ? "\n" : ",\n");
    printf("%*s{\"%s\":\"", IND_JSON * 2, "", _(HOST_STR));
    print_nameaddr(at, host[at].current, -1);
    printf("\"%c\"%s\":%d%c\"%s\":\"%s\"", DIV_JSON, _(HOP_STR), at + 1,
      DIV_JSON, _(ACTIVE_STR), _(host[at].up ? YES_STR : NO_STR));
    foreach_stat(at, json_statline, 0);
#ifdef WITH_IPINFO
    if (ipinfo_ready()) {
      char info[NAMELEN] = {0};
      ipinfo_data_div(info, sizeof(info), at, host[at].current, DIV_JSON);
      if (info[0])
        printf("%c\"%s\":[%s]", DIV_JSON, _(IPINFO_STR), info);
    }
#endif
    printf("}");
  }
  printf("\n%*s]", IND_JSON, "");
  if (tgterr_txt[0])
    printf("%c\"%s\":\"%s\"", DIV_JSON, _(ERROR_STR), tgterr_txt);
  printf("}");
}
#endif


#ifdef OUTPUT_FORMAT_TOON

void toon_head(uint n_targets) {
  PRINT_DATETIME("%s: \"%s\"\n", _(DATETIME_STR), date);
  printf("%s: %s\n", SOURCE_STR, srchost);
  if (mtr_optc > 0) {
    printf("%s[%d]:", ARGS_STR, mtr_optc);
    for (uint i = 0; i < mtr_optc; i++) {
      if (i) putchar(DIV_TOON);
      printf(" \"%s\"", mtr_optv[i]);
    }
    putchar('\n');
  }
  printf("%s[%d]:\n", TARGETS_STR, n_targets);
}

static void toon_headline(int at UNUSED, const t_stat *stat) {
  if (stat->key != BLANK_INDICATOR)
    printf("%c\"%s\"", DIV_TOON, stat->name);
}

static void toon_statline(int at, const t_stat *stat) {
  const char *elem = net_elem(at, stat->key);
  if (!elem) return;
  int len = strnlen(elem, NETELEM_MAXLEN);
  if (len > 0) {
    const char *q = QUOTE(elem, DIV_TOON);
    if (elem[len - 1] == '%') // print '%' with name
      printf("%c%s%.*s%s", DIV_TOON, q, len - 1, elem, q);
    else
      printf("%c%s%s%s",   DIV_TOON, q,          elem, q);
  }
}

void toon_close(void) {
  printf("%*s- %s: %s\n", IND_TOON, "", _(TARGET_STR), dsthost);
  int min = net_min(), max = net_max();
  printf("%*s%s[%d]", IND_TOON * 2, "", _(DATA_STR), max - min);
  printf("{\"%s\"%c\"%s\"%c\"%s\"", _(HOST_STR), DIV_TOON, _(HOP_STR), DIV_TOON, _(ACTIVE_STR));
  foreach_stat(0, toon_headline, 0);
#ifdef WITH_IPINFO
  if (ipinfo_ready()) {
    char info[NAMELEN] = {0};
    ipinfo_head_div(info, sizeof(info), DIV_TOON);
    if (info[0])
      printf("%c%s", DIV_TOON, info);
  }
#endif
  printf("}:\n");
  for (int at = min; at < max; at++) {
    printf("%*s\"", IND_TOON * 3, ""); /*HOST_STR*/
    print_nameaddr(at, host[at].current, -1);
    printf("\"%c%d%c\"%s\"", DIV_TOON, at + 1/*HOP_STR*/, DIV_TOON,
      _(host[at].up ? YES_STR : NO_STR) /*ACTIVE_STR*/);
    foreach_stat(at, toon_statline, 0);
#ifdef WITH_IPINFO
    if (ipinfo_ready()) {
      char info[NAMELEN] = {0};
      ipinfo_data_div(info, sizeof(info), at, host[at].current, DIV_TOON);
      if (info[0])
        printf("%c%s", DIV_TOON, info);
    }
#endif
    putchar('\n');
  }
  if (tgterr_txt[0])
    printf("%*s%s: \"%s\"\n", IND_TOON * 2, "", _(ERROR_STR), tgterr_txt);
}

#endif


#ifdef OUTPUT_FORMAT_CSV

void csv_head(void) {
  PRINT_DATETIME("%s%c\"%s\"\n", _(DATETIME_STR), DIV_CSV, date);
  printf("%s%c%s\n", SOURCE_STR, DIV_CSV, srchost);
  if (mtr_args[0]) {
    const char *q = QUOTE(mtr_args, DIV_CSV);
    printf("%s%c%s%s%s\n", ARGS_STR, DIV_CSV, q, mtr_args, q);
  }
  putchar('\n');
}

static void csv_headline(int at UNUSED, const t_stat *stat) {
  if (stat->key != BLANK_INDICATOR)
    printf("%c%s", DIV_CSV, stat->name ? stat->name : "");
}

static void csv_bodyline(int at, const t_stat *stat) {
  if (stat->key != BLANK_INDICATOR) {
    const char *str = net_elem(at, stat->key);
    printf("%c%s", DIV_CSV, str ? str : "");
  }
}

static inline void csv_body(int at) {
  printf("%d%c", at + 1, DIV_CSV);
  print_nameaddr(at, host[at].current, -1);
  //
  foreach_stat(at, csv_bodyline, DIV_CSV);
#ifdef WITH_IPINFO
  if (ipinfo_ready()) {
    char info[NAMELEN] = {0};
    ipinfo_data_div(info, sizeof(info), at, host[at].current, DIV_CSV);
    if (info[0])
      printf("%s", info);
  }
#endif
  putchar('\n');
}

void csv_close(bool next) {
  if (next) printf("\n");
  printf("%s%c%s\n", TARGET_STR, DIV_CSV, dsthost);
  printf("%s%c%s", HOP_STR, DIV_CSV, HOST_STR);
  foreach_stat(0, csv_headline, 0);
#ifdef WITH_IPINFO
  if (ipinfo_ready()) {
    char info[NAMELEN] = {0};
    ipinfo_head_div(info, sizeof(info), DIV_CSV);
    if (info[0])
      printf("%c%s", DIV_CSV, info);
  }
#endif
  putchar('\n');
  int max = net_max();
  for (int at = net_min(); at < max; at++)
    csv_body(at);
  if (tgterr_txt[0])
    printf("%s%c%s\n", (ERROR_STR), DIV_CSV, tgterr_txt);
}

#endif


#ifdef OUTPUT_FORMAT_RAW

void raw_rawping(int at, int usec) {
#ifdef ENABLE_DNS
  static bool raw_printed_name[MAXHOST];
  if (!raw_printed_name[at]) {
    const char *name = dns_ptr_lookup(at, host[at].current);
    if (name) {
      printf("d %d %s\n", at, name);
      if (!raw_printed_name[at])
        raw_printed_name[at] = true;
    }
  }
#endif
  LENVALMIL((double)usec / MIL);
  printf("p %d %.*f\n", at, _l, _v); // ping in msec
  fflush(stdout);
}

void raw_rawhost(int at, t_ipaddr *ipaddr) {
  printf("h %d %s\n", at, strlongip(ipaddr));
  fflush(stdout);
}
#endif

