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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>

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

extern char LocalHostname[];
extern char *Hostname;
extern int packetsize;
extern int bitpattern;
extern int tos;
extern int MaxPing;
extern int reportwide;

char *get_time_string(time_t now) {
  char *t = ctime(&now);
  t[strlen(t) - 1] = 0; // remove the trailing newline
  return t;
}

void report_open(void) {
  printf("Local host: %s\n", LocalHostname);
  printf("Start time: %s\n", get_time_string(time(NULL)));
}

static size_t snprint_addr(char *dst, size_t len, ip_t *addr) {
  if (unaddrcmp(addr)) {
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

void print_mpls(struct mplslen *m) {
#define MPLS_LINE_FMT "%4s[MPLS: Lbl %lu Exp %u S %u TTL %u]"
  if (m)
    for (int i = 0; i < m->labels; i++)
      printf(MPLS_LINE_FMT "\n", "", m->label[i], m->exp[i], m->s[i], m->ttl[i]);
}

int get_longest_name(int min, int max) {
  char *buf = malloc(max);
  assert(buf);
  int l = min;
  int m = net_max();
  for (int at = net_min(); at < m; at++) {
    int n = snprint_addr(buf, max, &host[at].addr);
    if (n > l)
      l = n;
  }
  free(buf);
  return l;
}

int found_addr_in_addrs(int z, ip_t *addr, ip_t *addrs) {
  for (int w = 0; w < z; w++) { // Ok... checking if there are ips repeated on same hop
    if (!addrcmp(addr, &(addrs[w])))
      return 1;
  }
  return 0;
}


void report_close(void) {
  assert(LSIDE_LEN < MAXDNAME);
  char *lbuf = calloc(1, MAXDNAME);	// left side
  assert(lbuf);
  char *rbuf = calloc(1, MAXDNAME);	// right side
  assert(rbuf);

  int len = get_longest_name(strlen(HOSTTITLE), MAXDNAME);
  char fmt[16];
  char lfmt[16];	// left side format
  char dfmt[16];

  // header: left
#ifdef IPINFO
  if (ii_ready()) {
    snprintf(lfmt, sizeof(lfmt), "%%2d. %%-%ds %%-%ds", ii_getwidth(), len); // "at. IPINFO HOST"
    snprintf(dfmt, sizeof(dfmt), "    %%-%ds %%-%ds", ii_getwidth(), len);
    snprintf(lbuf, MAXDNAME, dfmt, ii_getheader(), HOSTTITLE);
  } else
#endif
  {
    snprintf(lfmt, sizeof(lfmt), "%%2d. %%-%ds", len); // "at. HOST"
    snprintf(dfmt, sizeof(dfmt), "    %%-%ds", len);
    snprintf(lbuf, MAXDNAME, dfmt, HOSTTITLE);
  }

  // header: right
  for (int i = 0, r = 0; i < sizeof(fld_active); i++) {
    int j = fld_index[fld_active[i]];
    if (j >= 0) {
      snprintf(fmt, sizeof(fmt), "%%%ds", data_fields[j].length);
      r += snprintf(rbuf + r, MAXDNAME - r, fmt, data_fields[j].title);
    }
  }

  // header: left + right
  if (!reportwide)
    if (strlen(lbuf) >= LSIDE_LEN)
      lbuf[LSIDE_LEN] = 0;
  // without space between because all the fields on the right side are supposed to be with some indent
  printf("%s%s\n", lbuf, rbuf);


  // body
  char *name = calloc(1, MAXDNAME);
  assert(name);
  int max = net_max();

  for (int at = net_min(); at < max; at++) {
    ip_t *addr = &host[at].addr;
    snprint_addr(name, MAXDNAME, addr);

    // body: left
#ifdef IPINFO
    if (ii_ready())
      snprintf(lbuf, MAXDNAME, lfmt, at + 1, fmt_ipinfo(addr), name);
    else
#endif
      snprintf(lbuf, MAXDNAME, lfmt, at + 1, name);

    // body: right
#define REPORT_FLD1(factor) { r += snprintf(rbuf + r, MAXDNAME - r, data_fields[j].format, net_elem(at, data_fields[j].key) factor); }
    for (int i = 0, r = 0; i < sizeof(fld_active); i++) {
      int j = fld_index[fld_active[i]];
// j=0 fmt=" " elem=0: printed as " " with printf(" ", 0)
      if (j > 0) {
        if (index(data_fields[j].format, 'f'))
          REPORT_FLD1(/1000.0)
        else
          REPORT_FLD1();
      }
    }

    // body: left + right
    if (!reportwide)
      if (strlen(lbuf) >= LSIDE_LEN)
        lbuf[LSIDE_LEN] = 0;
    // without space between because all the fields on the right side are with space-indent
    printf("%s%s\n", lbuf, rbuf);


    // body-extra-lines: multipath, mpls, etc.
    struct mplslen *mpls = &host[at].mpls;
    ip_t *addrs = host[at].addrs;
    int z = 1;
    for (int z = 1; z < MAXPATH ; z++) { // z is starting at 1 because addrs[0] is the same that addr
      ip_t *addr2 = addrs + z;
      struct mplslen *mplss = &(host[at].mplss[z]);
      if (!unaddrcmp(addr2))	// break from loop at the first unassigned
        break;

      if (!found_addr_in_addrs(z, addr2, addrs)) {
        if ((mpls->labels) && (z == 1) && enablempls)
          print_mpls(mpls);
        snprint_addr(name, MAXDNAME, addr2);
#ifdef IPINFO
        if (ii_ready())
          snprintf(lbuf, MAXDNAME, dfmt, fmt_ipinfo(addr2), name);
        else
#endif
          snprintf(lbuf, MAXDNAME, dfmt, name);
        printf("%s\n", lbuf);
        if (enablempls)
          print_mpls(mplss);
      }
    }

    if (mpls->labels && (z == 1) && enablempls) // no multipath?
      print_mpls(mpls);
  }

  free(name);
  free(rbuf);
  free(lbuf);
}


#ifdef OUTPUT_FORMAT_TXT
void txt_close(void) {
  report_close();
}
#endif


#ifdef OUTPUT_FORMAT_XML
#define XML_MARGIN1	4
#define XML_MARGIN2	8
void xml_close(void) {
  char *buf = calloc(1, MAXDNAME);
  assert(buf);

  printf("<?xml version=\"1.0\"?>\n");
  printf("<MTR SRC=\"%s\" DST=\"%s\"", LocalHostname, Hostname);
  printf(" TOS=\"0x%X\"", tos);
  printf(" PSIZE=\"%d\"", packetsize);
  printf(" BITPATTERN=\"0x%02X\"", (unsigned char) abs(bitpattern));
  printf(" TESTS=\"%d\">\n", MaxPing);

  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    snprint_addr(buf, MAXDNAME, &host[at].addr);
    printf("%*s<HUB COUNT=\"%d\" HOST=\"%s\">\n", XML_MARGIN1, " ", at + 1, buf);

    for (int i = 0; i < MAXFLD; i++) {
      int j = fld_index[fld_active[i]];
      if (j > 0) {
#define REPORT_FLD2(factor) { snprintf(buf, MAXDNAME, data_fields[j].format, \
  net_elem(at, data_fields[j].key) factor ); }
        // 1000.0 is a temporary hack for stats usec to ms, impacted net_loss
        if (index(data_fields[j].format, 'f'))
          REPORT_FLD2(/1000.)
        else
          REPORT_FLD2();
        printf("%*s<%s>%s</%s>\n", XML_MARGIN2, " ", data_fields[j].title, trim(buf), data_fields[j].title);
      }
    }
#ifdef IPINFO
      if (ii_ready())
        printf("%*s<IPInfo>%s</IPInfo>\n", XML_MARGIN2, " ", fmt_ipinfo(&host[at].addr));
#endif
    printf("%*s</HUB>\n", XML_MARGIN1, " ");
  }
  printf("</MTR>\n");
  free(buf);
}
#endif


#ifdef OUTPUT_FORMAT_CSV
#define COMA	";"

void prupper(const char *str) {
  while (*str)
    putchar(toupper((int) *str++));
}


void csv_close(time_t now) {
  char *buf = calloc(1, MAXDNAME);
  assert(buf);

  printf("PROGRAM" COMA "TIME" COMA "DESTINATION" COMA "HOP" COMA "STATUS" COMA "HOSTNAME/IP");
#ifdef IPINFO
  if (ii_ready())
    printf(COMA "IPINFO");
#endif
  for (int i = 0; i < MAXFLD; i++) {
    int j = fld_index[fld_active[i]];
    if (j > 0) {
      printf(COMA);
      prupper(data_fields[j].title);
    }
  }
  printf("\n");

  int max = net_max();
  for (int at = net_min(); at < max; at++) {
    ip_t *addr = &host[at].addr;
    snprint_addr(buf, MAXDNAME, addr);

    printf("%s-%s", PACKAGE_NAME, MTR_VERSION);
    printf(COMA "%s", get_time_string(now));
    printf(COMA "%s", Hostname);
    printf(COMA "%d", at + 1);
    printf(COMA "%s", host[at].up ? "up" : "down");
    printf(COMA "%s", buf);
#ifdef IPINFO
    if (ii_ready())
      printf(COMA "%s", fmt_ipinfo(addr));
#endif

    for (int i = 0; i < MAXFLD; i++) {
      int j = fld_index[fld_active[i]];
      if (j > 0) {
        // 1000.0 is a temporary hack for stats usec to ms, impacted net_loss
        if (index(data_fields[j].format, 'f'))
          printf(COMA "%.2f", net_elem(at, data_fields[j].key) / 1000.);
        else
          printf(COMA "%d", net_elem(at, data_fields[j].key));
      }
    }
    printf("\n");
  }
  free(buf);
}
#endif


#ifdef OUTPUT_FORMAT_RAW
int enable_raw;
static int havename[MaxHost];

void raw_rawping(int at, int msec) {
  if (!havename[at]) {
    const char *name = dns_lookup(&host[at].addr);
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

