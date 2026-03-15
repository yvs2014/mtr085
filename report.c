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

static size_t snprint_addr(char *buf, size_t size, int at, int ndx) {
  if (!buf || !size) return 0;
  t_ipaddr *ipaddr = &IP_AT_NDX(at, ndx);
  if (addr_exist(ipaddr)) {
#ifdef ENABLE_DNS
    const char *name = run_opts.dns ? dns_ptr_cache(at, ndx) : NULL;
    if (name) {
      int inc = snprintf(buf, size, "%s", name);
      size_t len = (inc > 0) ? inc : 0;
      if (run_opts.ips) {
        inc = snprintf(buf + len, size - len, " (%s)", strlongip(ipaddr));
        if (inc > 0) len += inc;
      }
      return len;
    }
#endif
    int inc = snprintf(buf, size, "%s", strlongip(ipaddr));
    return (inc > 0) ? inc : 0;
  }
  int inc = snprintf(buf, size, "%s", UNKN_ITEM);
  return (inc > 0) ? inc : 0;
}

#ifdef WITH_MPLS
static void print_mpls(const mpls_data_t *mpls) {
  for (int i = 0; i < mpls->n; i++)
    printf("%s\n", mpls2str(&mpls->label[i], 4));
}
#endif

static size_t get_longest_name(size_t min, size_t max) {
  char buf[max];
  int nmax = net_max();
  for (int at = net_min(); at < nmax; at++) {
    for (int i = 0; i < MAXPATH; i++) {
      size_t len = snprint_addr(buf, max, at, i);
      if (len > min)
        min = len;
    }
  }
  return min;
}

#ifdef ENABLE_DNS
void report_resolv(void) {
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
static void report_info(int infolen, const char *info) {
  if (!infolen) return;
  if (info) {
    int len = infolen - ustrlen(info) + 1;
    printf("%s%*s", info, (len < 0) ? 0 : len, "");
  } else printf("%*s", infolen + 1, "");
}
#define REPORT_INFO(a, b) report_info(a, b)
#else
#define REPORT_INFO(a, b) NOOP
#endif

static void report_headstat(int at UNUSED, const t_stat *stat) {
  if (stat->name) {
    int pad = stat->min - stat->len;
    printf("%*s%s", (pad > 0) ? pad : 1, "", stat->name);
  } else printf("%*s", stat->min, "");
}

static void report_print_header(int hostlen, int infolen) {
  printf("%*s", IND_REP, "");
  // left
  REPORT_INFO(infolen, ipinfo_head_fix());
  { printf("%s", HOST_STR);
    int len = hostlen - ustrlen(HOST_STR);
    if (len > 0) printf("%*s", len, ""); }
  // right
  foreach_stat(0, report_headstat, '\n');
}

static void report_bodystat(int at, const t_stat *stat) {
  const char *str = net_elem(at, stat->key);
  if (str) {
    int pad = stat->min - strnlen(str, stat->min);
    printf("%*s%s", (pad > 0) ? pad : 1, "", str);
  } else
    printf("%*s", stat->min, "");
}

static void report_print_body(int at, const char *fmt, int hostlen, int infolen) {
  // body: left
  if (fmt) printf(fmt, at + 1);
  REPORT_INFO(infolen, ipinfo_data_fix(at, host[at].current));
  { char name[MAXDNAME] = {0};
    snprint_addr(name, sizeof(name), at, host[at].current);
    printf("%-*s", hostlen, name); }
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
    REPORT_INFO(infolen, ipinfo_data_fix(at, i));
    { char name[MAXDNAME] = {0};
      snprint_addr(name, sizeof(name), at, i);
      printf("%-*s\n", hostlen, name); }
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
  int hostlen = get_longest_name(ustrlen(HOST_STR), MAXDNAME) + 1;
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
  printf("<MTR SRC=\"%s\"",         srchost);
  printf(" QOS=\"0x%X\"",           run_opts.qos);
  printf(" PSIZE=\"%d\"",           run_opts.size);
  printf(" BITPATTERN=\"0x%02X\"",  abs(run_opts.pattern));
  printf(" TESTS=\"%d\">\n",        run_opts.cycles);
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
    char buf[MAXDNAME] = {0};
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%*s<HOP TTL=\"%d\" HOST=\"%s\">\n", IND_XML * 2, "", at + 1, buf);
    foreach_stat(at, xml_statline, 0);
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      printf("%*s<IPINFO>[%s]</IPINFO>\n", IND_XML * 3, "",
        ipinfo_data_div(at, host[at].current, DIV_XML));
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
  int len = strlen(elem);
  if (len <= 0) return;
  if (len > NETELEM_MAXLEN)
    len = NETELEM_MAXLEN;
  const char *q = QUOTE(elem, DIV_JSON);
  if (elem[len - 1] == '%') // print '%' with name
    printf("%c\"%s%%\":%s%.*s%s", DIV_JSON, stat->name, q, len - 1, elem, q);
  else
    printf("%c\"%s\":%s%s%s", DIV_JSON, stat->name, q, elem, q);
}

void json_close(bool next) {
  if (next) printf(",");
  printf("\n%*s{\"%s\":\"%s\"", IND_JSON, "", _(TARGET_STR), dsthost);
  printf("%c\"%s\":[", DIV_JSON, _(DATA_STR));
  int min = net_min(), max = net_max();
  for (int at = min; at < max; at++) {
    char buf[MAXDNAME] = {0};
    printf((at == min) ? "\n" : ",\n");
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%*s{\"%s\":\"%s\"%c\"%s\":%d%c\"%s\":\"%s\"", IND_JSON * 2, "",
      _(HOST_STR), buf, DIV_JSON, _(HOP_STR), at + 1, DIV_JSON,
      _(ACTIVE_STR), _(host[at].up ? YES_STR : NO_STR));
    foreach_stat(at, json_statline, 0);
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      printf("%c\"%s\":[%s]", DIV_JSON, _(IPINFO_STR),
        ipinfo_data_div(at, host[at].current, DIV_JSON));
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
  int len = strlen(elem);
  if (len <= 0) return;
  if (len > NETELEM_MAXLEN)
    len = NETELEM_MAXLEN;
  const char *q = QUOTE(elem, DIV_TOON);
  if (elem[len - 1] == '%') // print '%' with name
    printf("%c%s%.*s%s", DIV_TOON, q, len - 1, elem, q);
  else
    printf("%c%s%s%s", DIV_TOON, q, elem, q);
}

void toon_close(void) {
  printf("%*s- %s: %s\n", IND_TOON, "", _(TARGET_STR), dsthost);
  int min = net_min(), max = net_max();
  printf("%*s%s[%d]", IND_TOON * 2, "", _(DATA_STR), max - min);
  printf("{\"%s\"%c\"%s\"%c\"%s\"", _(HOST_STR), DIV_TOON, _(HOP_STR), DIV_TOON, _(ACTIVE_STR));
  foreach_stat(0, toon_headline, 0);
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    printf("%c%s", DIV_TOON, ipinfo_head_div(DIV_TOON));
#endif
  printf("}:\n");
  for (int at = min; at < max; at++) {
    char buf[MAXDNAME] = {0};
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%*s\"%s\"%c%d%c\"%s\"", IND_TOON * 3, "", buf/*HOST_STR*/, DIV_TOON,
      at + 1/*HOP_STR*/, DIV_TOON, _(host[at].up ? YES_STR : NO_STR) /*ACTIVE_STR*/);
    foreach_stat(at, toon_statline, 0);
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      printf("%c%s", DIV_TOON, ipinfo_data_div(at, host[at].current, DIV_TOON));
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
  char buf[MAXDNAME] = {0};
  snprint_addr(buf, sizeof(buf), at, host[at].current);
  printf("%d%c%s", at + 1, DIV_CSV, buf);
  //
  foreach_stat(at, csv_bodyline, DIV_CSV);
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    printf("%s", ipinfo_data_div(at, host[at].current, DIV_CSV));
#endif
  putchar('\n');
}

void csv_close(bool next) {
  if (next) printf("\n");
  printf("%s%c%s\n", TARGET_STR, DIV_CSV, dsthost);
  printf("%s%c%s", HOP_STR, DIV_CSV, HOST_STR);
  foreach_stat(0, csv_headline, 0);
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    printf("%c%s", DIV_CSV, ipinfo_head_div(DIV_CSV));
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

