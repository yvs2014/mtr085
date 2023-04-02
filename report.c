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
#include <ctype.h>
#include <assert.h>
#include <sys/types.h>
#include <time.h>
#include <arpa/nameser.h>

#include "config.h"
#include "mtr.h"
#include "version.h"
#include "report.h"
#include "net.h"
#include "dns.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif

#define HOSTTITLE	"Host"	// report mode
#define LSIDE_LEN	40	// non-wide report mode: left side of output

static char *get_time_string(time_t now) {
  char *t = ctime(&now);
  t[strnlen(t, 26) - 1] = 0; // remove the trailing newline
  return t;
}

void report_open(void) {
  printf("Local host: %s\n", srchost);
  printf("Start time: %s\n", get_time_string(time(NULL)));
}

static size_t snprint_addr(char *dst, size_t len, ip_t *addr) {
  if (addr_exist(addr)) {
    struct hostent *host = NULL;
    if (enable_dns) {
#ifdef ENABLE_IPV6
      if (af == AF_INET6)
        host = gethostbyaddr(addr, sizeof(struct in6_addr), af);
      else if (af == AF_INET)
#endif
        host = gethostbyaddr(addr, sizeof(struct in_addr), af);
    }
    if (host) {
      if (enable_dns && show_ips)
        return snprintf(dst, len, "%s (%s)", host->h_name, strlongip(addr));
      else
        return snprintf(dst, len, "%s", host->h_name);
    } else
      return snprintf(dst, len, "%s", strlongip(addr));
  } else
    return snprintf(dst, len, "%s", "???");
}

static void print_mpls(const mpls_data_t *m) {
  for (int i = 0; i < m->n; i++)
    printf("%s\n", mpls2str(&(m->label[i]), 4));
}

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
    ip_t *addr = &IP_AT_NDX(at, i);
    if (!addr_exist(addr))
      break; // done
    snprint_addr(bufname, MAXDNAME, addr);
#ifdef IPINFO
    if (ii_ready())
      snprintf(lbuf, MAXDNAME, dfmt, fmt_ipinfo(at, i), bufname);
    else
#endif
      snprintf(lbuf, MAXDNAME, dfmt, bufname);
    printf("%s\n", lbuf);
    if (enable_mpls)
      print_mpls(&MPLS_AT_NDX(at, i));
  }
}

#define REPORT_FACTOR(factor) snprintf(rbuf + r, MAXDNAME - r, data_fields[j].format, net_elem(at, data_fields[j].key) factor)

void report_close(bool wide) {
  assert(LSIDE_LEN < MAXDNAME);
  char *lbuf = calloc(1, MAXDNAME);	// left side
  assert(lbuf);
  char *rbuf = calloc(1, MAXDNAME);	// right side
  assert(rbuf);

  int len = get_longest_name(strlen(HOSTTITLE), MAXDNAME);
  char lfmt[32];	// left side format
  char dfmt[32];

  // header: left
#ifdef IPINFO
  if (ii_ready()) {
    snprintf(lfmt, sizeof(lfmt), "%%2d. %%-%ds %%-%ds", ii_getwidth(), len); // "at. IPINFO HOST"
    snprintf(dfmt, sizeof(dfmt), "    %%-%ds %%-%ds", ii_getwidth(), len);
    char* h = ii_getheader();
    snprintf(lbuf, MAXDNAME, dfmt, h ? h : "", HOSTTITLE);
  } else
#endif
  {
    snprintf(lfmt, sizeof(lfmt), "%%2d. %%-%ds", len); // "at. HOST"
    snprintf(dfmt, sizeof(dfmt), "    %%-%ds", len);
    snprintf(lbuf, MAXDNAME, dfmt, HOSTTITLE);
  }

  { // header: right
  char fmt[16];
  for (int i = 0, r = 0; i < sizeof(fld_active); i++) {
    int j = fld_index[fld_active[i]];
    if (j >= 0) {
      snprintf(fmt, sizeof(fmt), "%%%ds", data_fields[j].length);
      r += snprintf(rbuf + r, MAXDNAME - r, fmt, data_fields[j].title);
    }
  }
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
    ip_t *addr = &CURRENT_IP(at);
    snprint_addr(bufname, MAXDNAME, addr);

    // body: left
#ifdef IPINFO
    if (ii_ready())
      snprintf(lbuf, MAXDNAME, lfmt, at + 1, fmt_ipinfo(at, host[at].current), bufname);
    else
#endif
      snprintf(lbuf, MAXDNAME, lfmt, at + 1, bufname);

    // body: right
    for (int i = 0, r = 0; i < sizeof(fld_active); i++) {
      int j = fld_index[fld_active[i]];
      if (j > 0)
        r += (index(data_fields[j].format, 'f')) ? REPORT_FACTOR(/1000.0) : REPORT_FACTOR();
    }

    // body: left + right
    if (!wide)
      if (strlen(lbuf) >= LSIDE_LEN)
        lbuf[LSIDE_LEN] = 0;
    // without space between because all the fields on the right side are with space-indent
    printf("%s%s\n", lbuf, rbuf);

    if (enable_mpls)
      print_mpls(&CURRENT_MPLS(at));

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
#define XML_FACTOR(factor) snprintf(buf, MAXDNAME, data_fields[j].format, net_elem(at, data_fields[j].key) factor)

void xml_head(void) {
  printf("<?xml version=\"1.0\"?>\n");
  printf("<MTR SRC=\"%s\"", srchost);
  printf(" TOS=\"0x%X\"", tos);
  printf(" PSIZE=\"%d\"", packetsize);
  printf(" BITPATTERN=\"0x%02X\"", (unsigned char)abs(bitpattern));
  printf(" TESTS=\"%d\">\n", max_ping);
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
      int j = fld_index[fld_active[i]];
      if (j > 0) {
        // 1000.0 is a temporary hack for stats usec to ms, impacted net_loss
        (index(data_fields[j].format, 'f')) ?  XML_FACTOR(/1000.) : XML_FACTOR();
        printf("%*s<%s>%s</%s>\n", XML_MARGIN * 3, "", data_fields[j].title, trim(buf), data_fields[j].title);
      }
    }
#ifdef IPINFO
    if (ii_ready())
      printf("%*s<IpInfo>[%s]</IpInfo>\n", XML_MARGIN * 3, "", sep_ipinfo(at, host[at].current, ','));
#endif
    printf("%*s</HOP>\n", XML_MARGIN * 2, "");
  }
  printf("%*s</DST>\n", XML_MARGIN, "");
  free(buf);
}
#endif


#ifdef OUTPUT_FORMAT_JSON

#define JSON_MARGIN 4
#define JSON_FACTOR(factor) snprintf(buf, MAXDNAME, data_fields[j].format, net_elem(at, data_fields[j].key) factor)

void json_head(void) { printf("["); }
void json_tail(void) { printf("\n]\n"); }

void json_close(bool notfirst) {
  char *buf = calloc(1, MAXDNAME);
  assert(buf);
  if (notfirst)
    printf(",");
  printf("\n%*s{\"destination\":\"%s\",\"data\":[", JSON_MARGIN, "", dsthost);
  int min = net_min(), max = net_max();
  for (int at = min; at < max; at++) {
    ip_t *addr = &CURRENT_IP(at);
    printf((at == min) ? "\n" : ",\n");
    snprint_addr(buf, MAXDNAME, addr);
    printf("%*s{\"host\":\"%s\",\"hop\":%d,\"up\":%d", JSON_MARGIN * 2, "", buf, at + 1, host[at].up);
    for (int i = 0; i < MAXFLD; i++) {
      int j = fld_index[fld_active[i]];
      if (j > 0) {
        // 1000.0 is a temporary hack for stats usec to ms, impacted net_loss
		int l = (index(data_fields[j].format, 'f')) ? JSON_FACTOR(/1000.) : JSON_FACTOR();
		if ((l > 0) && (buf[l - 1] == '%')) buf[l - 1] = 0;
        printf(",\"%s\":%s", data_fields[j].title, trim(buf));
      }
    }
#ifdef IPINFO
    if (ii_ready())
      printf(",\"ipinfo\":[%s]", sep_ipinfo(at, host[at].current, ','));
#endif
    printf("}");
  }
  printf("\n%*s]}", JSON_MARGIN, "");
  free(buf);
}
#endif


#ifdef OUTPUT_FORMAT_CSV

#define CSV_DELIMITER	";"
#define COMA	','

static void prupper(const char *str) {
  while (*str)
    putchar(toupper((int) *str++));
}


void csv_close(bool notfirst) {
  char *buf = calloc(1, MAXDNAME);
  assert(buf);

  if (notfirst)
    printf("\n");
  printf("DESTINATION" CSV_DELIMITER "HOP" CSV_DELIMITER "STATUS" CSV_DELIMITER "HOST");
#ifdef IPINFO
  if (ii_ready())
    printf(CSV_DELIMITER "INFO");
#endif
  for (int i = 0; i < MAXFLD; i++) {
    int j = fld_index[fld_active[i]];
    if (j > 0) {
      printf(CSV_DELIMITER);
      prupper(data_fields[j].title);
    }
  }
  printf("\n");
  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    ip_t *addr = &CURRENT_IP(at);
    snprint_addr(buf, MAXDNAME, addr);

    printf("%s", dsthost);
    printf(CSV_DELIMITER "%d", at + 1);
    printf(CSV_DELIMITER "%s", host[at].up ? "up" : "down");
    printf(CSV_DELIMITER "%s", buf);
#ifdef IPINFO
    if (ii_ready())
      printf(CSV_DELIMITER "%s", sep_ipinfo(at, host[at].current, COMA));
#endif

    for (int i = 0; i < MAXFLD; i++) {
      int j = fld_index[fld_active[i]];
      if (j > 0) {
        // 1000.0 is a temporary hack for stats usec to ms, impacted net_loss
        (index(data_fields[j].format, 'f')) ?
          printf(CSV_DELIMITER "%.1f", net_elem(at, data_fields[j].key) / 1000.) :
          printf(CSV_DELIMITER "%d", net_elem(at, data_fields[j].key));
      }
    }
    printf("\n");
  }
  free(buf);
}
#endif


#ifdef OUTPUT_FORMAT_RAW

bool enable_raw = false; // global var
static int havename[MAXHOST];

void raw_rawping(int at, int msec) {
  if (!havename[at]) {
    const char *name = dns_ptr_lookup(at, host[at].current);
    if (name) {
      havename[at]++;
      printf("d %d %s\n", at, name);
    }
  }
  printf("p %d %d\n", at, msec);
  fflush(stdout);
}

void raw_rawhost(int at, ip_t * ip_addr) {
  printf("h %d %s\n", at, strlongip(ip_addr));
  fflush(stdout);
}
#endif

