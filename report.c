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
#include <time.h>

#include "config.h"
#ifdef OUTPUT_FORMAT_CSV
#include <ctype.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "common.h"

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

#define HOSTTITLE "Host"

static time_t started_at;

static char *at_time_str(time_t at, char *str, size_t size) {
  if (!str || !size) return NULL;
  str[0] = 0;
#ifdef HAVE_LOCALTIME_R
  struct tm re;
  struct tm *tm = (at > 0) ? localtime_r(&at, &re) : NULL;
#else
  struct tm *tm = (at > 0) ? localtime(&at) : NULL;
#endif
  if (tm) strftime(str, size, "%F %T %z", tm);
  return str;
}

inline void report_started_at(void) { started_at = time(NULL); }

static size_t snprint_addr(char *buf, size_t size, int at, int ndx) {
  if (!buf || !size) return 0;
  t_ipaddr *ipaddr = &IP_AT_NDX(at, ndx);
  if (addr_exist(ipaddr)) {
#ifdef ENABLE_DNS
    const char *name = enable_dns ? dns_ptr_cache(at, ndx) : NULL;
    if (name) {
      size_t len = snprintf(buf, size, "%s", name);
      if (show_ips)
        len += snprintf(buf + len, size - len, " (%s)", strlongip(ipaddr));
      return len;
    }
#endif
    return snprintf(buf, size, "%s", strlongip(ipaddr));
  }
  return snprintf(buf, size, "%s", UNKN_ITEM);
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

#define INFOPATT "%-*s"
#define INDENT "    " // 4 x _

static void report_print_header(int hostlen, int infolen) {
  printf("%s", INDENT);
  // left
#ifdef WITH_IPINFO
  if (infolen) printf(INFOPATT " ", infolen, ipinfo_header());
#endif
  printf(INFOPATT, hostlen, HOSTTITLE);
  // right
  for (int i = 0; i < sizeof(fld_index); i++) {
    const struct statf *stat = active_statf(i);
    if (stat) printf("%*s", stat->len, stat->name); else break;
  }
  printf("\n");
}

static void report_print_body(int at, const char *fmt, int hostlen, int infolen) {
  // body: left
  if (fmt) printf(fmt, at + 1);
#ifdef WITH_IPINFO
  if (infolen) printf(INFOPATT " ", infolen, fmt_ipinfo(at, host[at].current));
#endif
  { char name[MAXDNAME] = {0};
    snprint_addr(name, sizeof(name), at, host[at].current);
    printf(INFOPATT, hostlen, name); }
  // body: right
  for (int i = 0; (i < sizeof(fld_index)); i++) {
    const struct statf *stat = active_statf(i);
    if (!stat) break;
    const char *str = net_elem(at, stat->key);
    printf("%*s", stat->len, str ? str : "");
  }
  printf("\n");
#ifdef WITH_MPLS
  if (enable_mpls) print_mpls(&CURRENT_MPLS(at));
#endif
}

static void report_print_rest(int at, int hostlen, int infolen) {
  for (int i = 0; i < MAXPATH; i++) {
    if (i == host[at].current)
      continue; // because already printed
    if (!addr_exist(&IP_AT_NDX(at, i)))
      break; // done
    printf("%s", INDENT);
#ifdef WITH_IPINFO
    if (infolen) printf(INFOPATT " ", infolen, fmt_ipinfo(at, i));
#endif
    { char name[MAXDNAME] = {0};
      snprint_addr(name, sizeof(name), at, i);
      printf(INFOPATT "\n", hostlen, name); }
#ifdef WITH_MPLS
    if (enable_mpls)
      print_mpls(&MPLS_AT_NDX(at, i));
#endif
  }
}
#undef INFOPATT
#undef INDENT


void report_close(bool next, bool with_header) {
  if (last_neterr != 0) return;
  if (next) printf("\n");
  if (with_header) {
    char str[32];
    char *tm = at_time_str(started_at, str, sizeof(str));
    printf("[%s] %s: %s %s %s\n", tm ? tm : "", srchost, FULLNAME, mtr_args, dsthost);
  }
  int hostlen = get_longest_name(strlen(HOSTTITLE), MAXDNAME);
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
  printf("<MTR SRC=\"%s\"", srchost);
  printf(" TOS=\"0x%X\"", tos);
  printf(" PSIZE=\"%d\"", cpacketsize);
  printf(" BITPATTERN=\"0x%02X\"", abs(cbitpattern));
  printf(" TESTS=\"%ld\">\n", max_ping);
}

void xml_tail(void) { printf("</MTR>\n"); }

void xml_close(void) {
  printf("%*s<DST HOST=\"%s\">\n", XML_MARGIN, "", dsthost);
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    char buf[MAXDNAME] = {0};
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%*s<HOP TTL=\"%d\" HOST=\"%s\">\n", XML_MARGIN * 2, "", at + 1, buf);
    for (int i = 0; i < sizeof(fld_index); i++) {
      const struct statf *stat = active_statf(i);
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
    printf("%*s<ERROR>%s</ERROR>\n", XML_MARGIN * 2, "", neterr_txt);
  printf("%*s</DST>\n", XML_MARGIN, "");
}
#endif


#ifdef OUTPUT_FORMAT_JSON

enum { JSON_MARGIN = 4 };

void json_head(void) { printf("{\"source\":\"%s\",\"args\":\"%s\",\"targets\":[", srchost, mtr_args); }
void json_tail(void) { printf("\n]}\n"); }

void json_close(bool next) {
  if (next) printf(",");
  { char str[32];
    char *tm = at_time_str(started_at, str, sizeof(str));
    printf("\n%*s{\"destination\":\"%s\",\"datetime\":\"%s\",\"data\":[",
      JSON_MARGIN, "", dsthost, tm ? tm : ""); }
  int min = net_min(), max = net_max();
  for (int at = min; at < max; at++) {
    char buf[MAXDNAME] = {0};
    printf((at == min) ? "\n" : ",\n");
    snprint_addr(buf, sizeof(buf), at, host[at].current);
    printf("%*s{\"host\":\"%s\",\"hop\":%d,\"up\":%d", JSON_MARGIN * 2, "", buf, at + 1, host[at].up);
    for (int i = 0; i < sizeof(fld_index); i++) {
      const struct statf *stat = active_statf(i);
      if (!stat) break;
      const char *str = net_elem(at, stat->key);
      if (str) {
        int len = strnlen(str, MAXDNAME);
        if ((len > 0) && (str[len - 1] == '%')) // trim '%' at the end
          printf(",\"%s%%\":%.*s", stat->name, len - 1, str);
        else
          printf(",\"%s\":%s", stat->name, str);
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
    printf(",\"error\":\"%s\"", neterr_txt);
  printf("}");
}
#endif


#ifdef OUTPUT_FORMAT_CSV

enum { CSV_DELIMITER = ';', CSV_HOSTINFO_DELIMITER = ',' };

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
  for (int i = 0; i < sizeof(fld_index); i++) {
    const struct statf *stat = active_statf(i);
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
  for (int i = 0; i < sizeof(fld_index); i++) {
    const struct statf *stat = active_statf(i);
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

bool enable_raw; // global var

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

