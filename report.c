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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <limits.h>

#ifdef OUTPUT_FORMAT_CSV
#include <ctype.h>
#endif
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

static time_t started_at;

void report_started_at(void) { started_at = time(NULL); }

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

#define INDENT "    " // 4 x _

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

static void report_print_header(int hostlen, int infolen) {
  printf("%s", INDENT);
  // left
  REPORT_INFO(infolen, ipinfo_header());
  { printf("%s", HOST_STR);
    int len = hostlen - ustrlen(HOST_STR);
    if (len > 0) printf("%*s", len, ""); }
  // right
  for (unsigned i = 0; i < sizeof(fld_index); i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    if (stat->name) {
      int pad = stat->min - stat->len;
      printf("%*s%s", (pad > 0) ? pad : 1, "", stat->name);
    } else printf("%*s", stat->min, "");
  }
  printf("\n");
}

static void report_print_body(int at, const char *fmt, int hostlen, int infolen) {
  // body: left
  if (fmt) printf(fmt, at + 1);
  REPORT_INFO(infolen, fmt_ipinfo(at, host[at].current));
  { char name[MAXDNAME] = {0};
    snprint_addr(name, sizeof(name), at, host[at].current);
    printf("%-*s", hostlen, name); }
  // body: right
  for (unsigned i = 0; i < sizeof(fld_index); i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    const char *str = net_elem(at, stat->key);
    if (str) {
      int pad = stat->min - strnlen(str, stat->min);
      printf("%*s%s", (pad > 0) ? pad : 1, "", str);
    } else printf("%*s", stat->min, "");
  }
  printf("\n");
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
    printf("%s", INDENT);
    REPORT_INFO(infolen, fmt_ipinfo(at, i));
    { char name[MAXDNAME] = {0};
      snprint_addr(name, sizeof(name), at, i);
      printf("%-*s\n", hostlen, name); }
#ifdef WITH_MPLS
    if (run_opts.mpls)
      print_mpls(&MPLS_AT_NDX(at, i));
#endif
  }
}
#undef INDENT


void report_close(bool next, bool with_header) {
  if (last_neterr != 0) return;
  if (next) printf("\n");
  if (with_header) {
    char str[64];
    const char *date = datetime(started_at, str, sizeof(str));
    printf("[%s] %s: %s %s %s\n", date ? date : "", srchost, PACKAGE_NAME, mtr_args, dsthost);
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
}


#ifdef OUTPUT_FORMAT_XML

enum { XML_MARGIN = 2 };

void xml_head(void) {
  printf("<?xml version=\"1.0\"?>\n");
  printf("<MTR SRC=\"%s\"",         srchost);
  printf(" QOS=\"0x%X\"",           run_opts.qos);
  printf(" PSIZE=\"%d\"",           run_opts.size);
  printf(" BITPATTERN=\"0x%02X\"",  abs(run_opts.pattern));
  printf(" TESTS=\"%d\">\n",        run_opts.cycles);
}

void xml_tail(void) { printf("</MTR>\n"); }

void xml_close(void) {
  printf("%*s<DST HOST=\"%s\">\n", XML_MARGIN, "", dsthost);
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    char buf[MAXDNAME] = {0};
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%*s<HOP TTL=\"%d\" HOST=\"%s\">\n", XML_MARGIN * 2, "", at + 1, buf);
    for (unsigned i = 0; i < sizeof(fld_index); i++) {
      const t_stat *stat = active_stats(i);
      if (!stat) break;
      const char *str = net_elem(at, stat->key);
      if (str)
        printf("%*s<%s>%s</%s>\n", XML_MARGIN * 3, "", stat->name, str, stat->name);
    }
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      printf("%*s<IpInfo>[%s]</IpInfo>\n", XML_MARGIN * 3, "", sep_ipinfo(at, host[at].current, ','));
#endif
    printf("%*s</HOP>\n", XML_MARGIN * 2, "");
  }
  if (last_neterr != 0)
    printf("%*s<ERROR>%s</ERROR>\n", XML_MARGIN * 2, "", err_fulltxt);
  printf("%*s</DST>\n", XML_MARGIN, "");
}
#endif


#ifdef OUTPUT_FORMAT_JSON

enum { JSON_MARGIN = 4 };

void json_head(void) { printf("{\"source\":\"%s\",\"args\":\"%s\",\"targets\":[", srchost, mtr_args); }
void json_tail(void) { printf("\n]}\n"); }

void json_close(bool next) {
  if (next) printf(",");
  { char str[64];
    const char *date = datetime(started_at, str, sizeof(str));
    printf("\n%*s{\"destination\":\"%s\",\"datetime\":\"%s\",\"data\":[",
      JSON_MARGIN, "", dsthost, date ? date : ""); }
  int min = net_min(), max = net_max();
  for (int at = min; at < max; at++) {
    char buf[MAXDNAME] = {0};
    printf((at == min) ? "\n" : ",\n");
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%*s{\"host\":\"%s\",\"hop\":%d,\"up\":%d", JSON_MARGIN * 2, "", buf, at + 1, host[at].up);
    for (unsigned i = 0; i < sizeof(fld_index); i++) {
      const t_stat *stat = active_stats(i);
      if (!stat) break;
      const char *elem = net_elem(at, stat->key);
      if (elem) {
        int len = strnlen(elem, NETELEM_MAXLEN);
        if (len > 0) {
          if (elem[len - 1] == '%') // print '%' with name
            printf(",\"%s%%\":%.*s", stat->name, len - 1, elem);
          else
            printf(",\"%s\":%s", stat->name, elem);
        }
      }
    }
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      printf(",\"ipinfo\":[%s]", sep_ipinfo(at, host[at].current, ','));
#endif
    printf("}");
  }
  printf("\n%*s]", JSON_MARGIN, "");
  if (last_neterr != 0)
    printf(",\"error\":\"%s\"", err_fulltxt);
  printf("}");
}
#endif


#ifdef OUTPUT_FORMAT_CSV

static const char CSV_DELIMITER = ';';
static const char CSV_HOSTINFO_DELIMITER = ',';

static inline void prupper(const char *str) { while (*str) putchar(toupper((int)*str++)); }

static inline void csv_body(int at) {
  printf("%s", dsthost);
  printf("%c%d", CSV_DELIMITER, at + 1);
  printf("%c%s", CSV_DELIMITER, host[at].up ? "up" : "down");
  { char buf[MAXDNAME] = {0};
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%c%s", CSV_DELIMITER, buf); }
#ifdef WITH_IPINFO
  if (ipinfo_ready()) printf("%c%s", CSV_DELIMITER, sep_ipinfo(at, host[at].current, CSV_HOSTINFO_DELIMITER));
#endif
  for (unsigned i = 0; i < sizeof(fld_index); i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    const char *str = net_elem(at, stat->key);
    if (str) printf("%c%s", CSV_DELIMITER, str);
    else if (stat->key == BLANK_INDICATOR) putchar(CSV_DELIMITER);
  }
  printf("\n");
}

void csv_close(bool next) {
  if (last_neterr != 0) return;
  if (next) printf("\n");
  printf("DESTINATION%cHOP%cSTATUS%cHOST", CSV_DELIMITER, CSV_DELIMITER, CSV_DELIMITER);
#ifdef WITH_IPINFO
  if (ipinfo_ready()) printf("%c%s", CSV_DELIMITER, "INFO");
#endif
  for (unsigned i = 0; i < sizeof(fld_index); i++) {
    const t_stat *stat = active_stats(i);
    if (!stat) break;
    putchar(CSV_DELIMITER);
    if (stat->key != BLANK_INDICATOR) prupper(stat->name);
  }
  printf("\n");
  int max = net_max();
  for (int at = net_min(); at < max; at++)
    csv_body(at);
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

