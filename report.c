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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
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
enum { HOSTINFO_LEN = 40 }; // non-wide report mode: left side of output

static char *get_now_str(void) {
  static char now_str[32];
  time_t now = time(NULL);
  strftime(now_str, sizeof(now_str), "%F %T %z", localtime(&now));
  return now_str;
}

void report_open(bool next) {
  if (next) printf("\n");
  printf("[%s] %s: %s %s %s\n", get_now_str(), srchost, FULLNAME, mtr_args, dsthost);
}

static size_t snprint_addr(char *dst, size_t len, t_ipaddr *ipaddr) {
  if (addr_exist(ipaddr)) {
#ifdef ENABLE_DNS
    struct hostent *host = NULL;
    if (enable_dns) {
#ifdef ENABLE_IPV6
      if (af == AF_INET6)
        host = gethostbyaddr(ipaddr, sizeof(ipaddr->in6), af);
      else if (af == AF_INET)
#endif
        host = gethostbyaddr(ipaddr, sizeof(ipaddr->in), af);
    }
    if (host) {
      if (enable_dns && show_ips)
        return snprintf(dst, len, "%s (%s)", host->h_name, strlongip(ipaddr));
      return snprintf(dst, len, "%s", host->h_name);
    }
#endif
    return snprintf(dst, len, "%s", strlongip(ipaddr));
  }
  return snprintf(dst, len, "%s", "???");
}

#ifdef WITH_MPLS
static void print_mpls(const mpls_data_t *mpls) {
  for (int i = 0; i < mpls->n; i++)
    printf("%s\n", mpls2str(&mpls->label[i], 4));
}
#endif

static int get_longest_name(int min, int max) {
  char buf[max];
  int nmax = net_max();
  for (int at = net_min(); at < nmax; at++) {
    for (int i = 0; i < MAXPATH; i++) {
      int len = snprint_addr(buf, max, &IP_AT_NDX(at, i));
      if (len > min)
        min = len;
    }
  }
  return min;
}

#define INFOPATT "%-*s"
#define INDENT "    " // 4 x _

static void report_print_header(int hostlen, int infolen, bool wide) {
  char buf[MAXDNAME] = {0};
  printf("%s", INDENT);
  // left
  int len = 0;
#ifdef WITH_IPINFO
  if (infolen) len += snprintf(buf, sizeof(buf), INFOPATT " ", infolen, ipinfo_header());
#endif
  snprintf(buf + len, sizeof(buf) - len, INFOPATT, hostlen, HOSTTITLE);
  if (!wide && (strnlen(buf, sizeof(buf)) >= HOSTINFO_LEN)) buf[HOSTINFO_LEN] = 0;
  printf("%s", buf);
  // right
  for (int i = 0, len = 0; (i < sizeof(fld_index)) && (len < sizeof(buf)); i++) {
    const struct statf *stat = active_statf(i);
    if (stat) printf("%*s", stat->len, stat->name); else break;
  }
  printf("\n");
}

static void report_print_body(int at, const char *fmt, int hostlen, int infolen, bool wide) {
  char buf[MAXDNAME] = {0};
  int len = 0;
  // body: left
  if (fmt) printf(fmt, at + 1);
#ifdef WITH_IPINFO
  if (infolen) len += snprintf(buf, sizeof(buf), INFOPATT " ", infolen, fmt_ipinfo(at, host[at].current));
#endif
  { char name[MAXDNAME] = {0};
    snprint_addr(name, sizeof(name), &CURRENT_IP(at));
    snprintf(buf + len, sizeof(buf) - len, INFOPATT, hostlen, name); }
  if (!wide && (strlen(buf) >= HOSTINFO_LEN)) buf[HOSTINFO_LEN] = 0;
  printf("%s", buf);
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
  char buf[MAXDNAME];
  for (int i = 0; i < MAXPATH; i++) {
    if (i == host[at].current)
      continue; // because already printed
    t_ipaddr *ipaddr = &IP_AT_NDX(at, i);
    if (!addr_exist(ipaddr))
      break; // done
    printf("%s", INDENT);
    buf[0] = 0;
    snprint_addr(buf, sizeof(buf), ipaddr);
#ifdef WITH_IPINFO
    if (infolen) printf(INFOPATT " ", infolen, fmt_ipinfo(at, i));
#endif
    printf(INFOPATT "\n", hostlen, buf);
#ifdef WITH_MPLS
    if (enable_mpls)
      print_mpls(&MPLS_AT_NDX(at, i));
#endif
  }
}
#undef INFOPATT
#undef INDENT


void report_close(bool wide) {
  if (last_neterr != 0) return;
  static_assert(HOSTINFO_LEN < MAXDNAME, "hostinfo len");
  int hostlen = get_longest_name(strlen(HOSTTITLE), MAXDNAME);
  int infolen =
#ifdef WITH_IPINFO
    ipinfo_ready() ? ipinfo_width() :
#endif
    0;
  report_print_header(hostlen, infolen, wide);
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    report_print_body(at, AT_FMT " ", hostlen, infolen, wide);
    report_print_rest(at, hostlen, infolen); // multipath, mpls, etc.
  }
}


#ifdef OUTPUT_FORMAT_TXT
void txt_close(bool next) {
  if (next) printf("\n");
  report_close(true);
}
#endif


#ifdef OUTPUT_FORMAT_XML

#define XML_MARGIN 2

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
    snprint_addr(buf, sizeof(buf), &CURRENT_IP(at));
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

#define JSON_MARGIN 4

void json_head(void) { printf("{\"source\":\"%s\",\"args\":\"%s\",\"targets\":[", srchost, mtr_args); }
void json_tail(void) { printf("\n]}\n"); }

void json_close(bool next) {
  if (next) printf(",");
  printf("\n%*s{\"destination\":\"%s\",\"datetime\":\"%s\",\"data\":[", JSON_MARGIN, "", dsthost, get_now_str());
  int min = net_min(), max = net_max();
  for (int at = min; at < max; at++) {
    char buf[MAXDNAME] = {0};
    printf((at == min) ? "\n" : ",\n");
    snprint_addr(buf, sizeof(buf),  &CURRENT_IP(at));
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

#define CSV_DELIMITER ";"
#define COMA ','

static inline void prupper(const char *str) { while (*str) putchar(toupper((int)*str++)); }

static inline void csv_body(int at) {
  printf("%s", dsthost);
  printf(CSV_DELIMITER "%d", at + 1);
  printf(CSV_DELIMITER "%s", host[at].up ? "up" : "down");
  { char buf[MAXDNAME] = {0};
    snprint_addr(buf, sizeof(buf), &CURRENT_IP(at));
    printf(CSV_DELIMITER "%s", buf); }
#ifdef WITH_IPINFO
  if (ipinfo_ready()) printf(CSV_DELIMITER "%s", sep_ipinfo(at, host[at].current, COMA));
#endif
  for (int i = 0; i < sizeof(fld_index); i++) {
    const struct statf *stat = active_statf(i);
    if (!stat) break;
    const char *str = net_elem(at, stat->key);
    if (str) printf(CSV_DELIMITER "%s", str);
  }
  printf("\n");
}

void csv_close(bool next) {
  if (last_neterr != 0) return;
  if (next) printf("\n");
  printf("DESTINATION" CSV_DELIMITER "HOP" CSV_DELIMITER "STATUS" CSV_DELIMITER "HOST");
#ifdef WITH_IPINFO
  if (ipinfo_ready()) printf(CSV_DELIMITER "INFO");
#endif
  for (int i = 0; i < sizeof(fld_index); i++) {
    const struct statf *stat = active_statf(i);
    if (!stat) break;
    if (isblank((int)stat->key) || (stat->key == '_')) continue;
    printf(CSV_DELIMITER);
    prupper(stat->name);
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

