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
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/in_systm.h>

#include "aux.h"
#include "report.h"
#include "net.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif

#include "config.h"
#ifdef OUTPUT_FORMAT_CSV
#include <ctype.h>
#endif

#ifndef MAXDNAME
#define MAXDNAME 1025
#endif

#define HOSTTITLE	"Host"	// report mode
#define LSIDE_LEN	40	// non-wide report mode: left side of output

static char *get_now_str(void) {
  static char now_str[32];
  time_t now = time(NULL);
  strftime(now_str, sizeof(now_str), "%F %T %z", localtime(&now));
  return now_str;
}

void report_open(bool notfirst) {
  if (notfirst)
    printf("\n");
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
      else
        return snprintf(dst, len, "%s", host->h_name);
    } else
#endif
    return snprintf(dst, len, "%s", strlongip(ipaddr));
  } else
    return snprintf(dst, len, "%s", "???");
}

#ifdef WITH_MPLS
static void print_mpls(const mpls_data_t *m) {
  for (int i = 0; i < m->n; i++)
    printf("%s\n", mpls2str(&(m->label[i]), 4));
}
#endif

static int get_longest_name(int min, int max) {
  char *buf = malloc(max);
  assert(buf);
  int l = min;
  int m = net_max();
  for (int at = net_min(); at < m; at++) {
    for (int i = 0; i < MAXPATH; i++) {
      int n = snprint_addr(buf, max, &IP_AT_NDX(at, i));
      if (n > l)
        l = n;
    }
  }
  free(buf);
  return l;
}

static void report_addr_extra(int at, char *bufname, char *lbuf, const char *dfmt) {
  for (int i = 0; i < MAXPATH; i++) {
    if (i == host[at].current)
      continue; // because already printed
    t_ipaddr *ipaddr = &IP_AT_NDX(at, i);
    if (!addr_exist(ipaddr))
      break; // done
    snprint_addr(bufname, MAXDNAME, ipaddr);
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      snprintf(lbuf, MAXDNAME, dfmt, fmt_ipinfo(at, i), bufname);
    else
#endif
      snprintf(lbuf, MAXDNAME, dfmt, bufname);
    printf("%s\n", lbuf);
#ifdef WITH_MPLS
    if (enable_mpls)
      print_mpls(&MPLS_AT_NDX(at, i));
#endif
  }
}


void report_close(bool wide) {
  if (last_neterr != 0)
    return;

  assert(LSIDE_LEN < MAXDNAME);
  char *lbuf = calloc(1, MAXDNAME);	// left side
  assert(lbuf);
  char *rbuf = calloc(1, MAXDNAME);	// right side
  assert(rbuf);

  int len = get_longest_name(strlen(HOSTTITLE), MAXDNAME);
  char lfmt[32];	// left side format
  char dfmt[32];

  // header: left
#ifdef WITH_IPINFO
  if (ipinfo_ready()) {
    snprintf(lfmt, sizeof(lfmt), "%%2d. %%-%ds %%-%ds", ipinfo_width(), len); // "at. IPINFO HOST"
    snprintf(dfmt, sizeof(dfmt), "    %%-%ds %%-%ds",   ipinfo_width(), len);
    char *h = ipinfo_header();
    snprintf(lbuf, MAXDNAME, dfmt, h ? h : "", HOSTTITLE);
  } else
#endif
  {
    snprintf(lfmt, sizeof(lfmt), "%%2d. %%-%ds", len); // "at. HOST"
    snprintf(dfmt, sizeof(dfmt), "    %%-%ds", len);
    snprintf(lbuf, MAXDNAME, dfmt, HOSTTITLE);
  }

  // header: right
  for (int i = 0, r = 0; (i < MAXFLD) && (r < MAXDNAME); i++) {
    const struct statf *sf = active_statf(i);
    if (sf)
      r += snprintf(rbuf + r, MAXDNAME - r, "%*s", sf->len, sf->name);
  }

  // header: left + right
  if (!wide)
    if (strlen(lbuf) >= LSIDE_LEN)
      lbuf[LSIDE_LEN] = 0;
  // without space between because all the fields on the right side are supposed to be with some indent
  printf("%s%s\n", lbuf, rbuf);

  // body
  char *bufname = calloc(1, MAXDNAME);
  assert(bufname);
  int max = net_max();

  for (int at = net_min(); at < max; at++) {
    snprint_addr(bufname, MAXDNAME, &CURRENT_IP(at));

    // body: left
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      snprintf(lbuf, MAXDNAME, lfmt, at + 1, fmt_ipinfo(at, host[at].current), bufname);
    else
#endif
      snprintf(lbuf, MAXDNAME, lfmt, at + 1, bufname);

    // body: right
    for (int i = 0, r = 0; (i < MAXFLD) && (r < MAXDNAME); i++) {
      const struct statf *sf = active_statf(i);
      if (sf) {
        const char *str = net_elem(at, sf->key);
        r += snprintf(rbuf + r, MAXDNAME - r, "%*s", sf->len, str ? str : "");
      }
    }

    // body: left + right
    if (!wide)
      if (strlen(lbuf) >= LSIDE_LEN)
        lbuf[LSIDE_LEN] = 0;
    // without space between because all the fields on the right side are with space-indent
    printf("%s%s\n", lbuf, rbuf);
#ifdef WITH_MPLS
    if (enable_mpls)
      print_mpls(&CURRENT_MPLS(at));
#endif
    // body-extra-lines: multipath, mpls, etc.
    report_addr_extra(at, bufname, lbuf, dfmt);
  }
  free(bufname);
  free(rbuf);
  free(lbuf);
}


#ifdef OUTPUT_FORMAT_TXT
void txt_close(bool notfirst) {
  if (notfirst)
    printf("\n");
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
  char *buf = calloc(1, MAXDNAME);
  assert(buf);
  printf("%*s<DST HOST=\"%s\">\n", XML_MARGIN, "", dsthost);
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    snprint_addr(buf, MAXDNAME, &CURRENT_IP(at));
    printf("%*s<HOP TTL=\"%d\" HOST=\"%s\">\n", XML_MARGIN * 2, "", at + 1, buf);
    for (int i = 0; i < MAXFLD; i++) {
      const struct statf *sf = active_statf(i);
      if (sf) {
        const char *str = net_elem(at, sf->key);
        if (str)
          printf("%*s<%s>%s</%s>\n", XML_MARGIN * 3, "", sf->name, str, sf->name);
      }
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
  free(buf);
}
#endif


#ifdef OUTPUT_FORMAT_JSON

#define JSON_MARGIN 4

void json_head(void) { printf("{\"source\":\"%s\",\"args\":\"%s\",\"targets\":[", srchost, mtr_args); }
void json_tail(void) { printf("\n]}\n"); }

void json_close(bool notfirst) {
  char *buf = malloc(MAXDNAME);
  assert(buf);
  if (notfirst)
    printf(",");
  printf("\n%*s{\"destination\":\"%s\",\"datetime\":\"%s\",\"data\":[", JSON_MARGIN, "", dsthost, get_now_str());
  int min = net_min(), max = net_max();
  for (int at = min; at < max; at++) {
    printf((at == min) ? "\n" : ",\n");
    snprint_addr(buf, MAXDNAME,  &CURRENT_IP(at));
    printf("%*s{\"host\":\"%s\",\"hop\":%d,\"up\":%d", JSON_MARGIN * 2, "", buf, at + 1, host[at].up);
    for (int i = 0; i < MAXFLD; i++) {
      const struct statf *sf = active_statf(i);
      if (sf) {
        const char *str = net_elem(at, sf->key);
        if (str) {
          int l = strnlen(str, MAXDNAME); // for trimming '%' at the end
          if ((l > 0) && (str[l - 1] == '%'))
            printf(",\"%s%%\":%.*s", sf->name, l - 1, str);
          else
            printf(",\"%s\":%s", sf->name, str);
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
    printf(",\"error\":\"%s\"", neterr_txt);
  printf("}");
  free(buf);
}
#endif


#ifdef OUTPUT_FORMAT_CSV

#define CSV_DELIMITER	";"
#define COMA	','

static inline void prupper(const char *s) { while (*s) putchar(toupper((int)*s++)); }

void csv_close(bool notfirst) {
  if (last_neterr != 0)
    return;
  char *buf = calloc(1, MAXDNAME);
  assert(buf);

  if (notfirst)
    printf("\n");
  printf("DESTINATION" CSV_DELIMITER "HOP" CSV_DELIMITER "STATUS" CSV_DELIMITER "HOST");
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    printf(CSV_DELIMITER "INFO");
#endif
  for (int i = 0; i < MAXFLD; i++) {
    const struct statf *sf = active_statf(i);
    if (sf && sf->key != ' ') {
      printf(CSV_DELIMITER);
      prupper(sf->name);
    }
  }
  printf("\n");
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    snprint_addr(buf, MAXDNAME, &CURRENT_IP(at));

    printf("%s", dsthost);
    printf(CSV_DELIMITER "%d", at + 1);
    printf(CSV_DELIMITER "%s", host[at].up ? "up" : "down");
    printf(CSV_DELIMITER "%s", buf);
#ifdef WITH_IPINFO
    if (ipinfo_ready())
      printf(CSV_DELIMITER "%s", sep_ipinfo(at, host[at].current, COMA));
#endif
    for (int i = 0; i < MAXFLD; i++) {
      const struct statf *sf = active_statf(i);
      if (sf) {
        const char *str = net_elem(at, sf->key);
        if (str)
          printf(CSV_DELIMITER "%s", str);
      }
    }
    printf("\n");
  }
  free(buf);
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

