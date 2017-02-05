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

#include <sys/types.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "mtr.h"
#include "version.h"
#include "report.h"
#include "net.h"
#include "dns.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif

#define MAXLOADBAL 5

extern char LocalHostname[];
extern char *Hostname;
extern int cpacketsize;
extern int bitpattern;
extern int tos;
extern int MaxPing;
extern int reportwide;


char *get_time_string (void) 
{
  time_t now; 
  char *t;
  now = time (NULL);
  t = ctime (&now);
  t [ strlen (t) -1] = 0; // remove the trailing newline
  return t;
}

void report_open(void) {
  printf("Local host: %s\n", LocalHostname);
  printf("Start time: %s\n", get_time_string());
}

static size_t snprint_addr(char *dst, size_t dst_len, ip_t *addr) {
  if (unaddrcmp(addr)) {
    struct hostent *host = NULL;
    if (enable_dns) {
#ifdef ENABLE_IPV6
      if (af == AF_INET6)
        host = gethostbyaddr(addr, sizeof(struct in6_addr), af);
      else /* if (af == AF_INET) */
#endif
        host = gethostbyaddr(addr, sizeof(struct in_addr), af);
    } else
      host = NULL;
    if (!host) return snprintf(dst, dst_len, "%s", strlongip(addr));
    else if (enable_dns && show_ips)
      return snprintf(dst, dst_len, "%s (%s)", host->h_name, strlongip(addr));
    else return snprintf(dst, dst_len, "%s", host->h_name);
  } else return snprintf(dst, dst_len, "%s", "???");
}

void print_mpls(struct mplslen *mpls) {
  int k;
  for (k=0; k < mpls->labels; k++)
    printf("       [MPLS: Lbl %lu Exp %u S %u TTL %u]\n", mpls->label[k], mpls->exp[k], mpls->s[k], mpls->ttl[k]);
}

#define ACTIVE_FLD_LOOP(statement) { \
  int i; \
  for (i=0; i < MAXFLD; i++) { \
    int j = fld_index[fld_active[i]]; \
    if (j < 0) \
      continue; \
    statement; \
  } \
  printf("%s\n", buf); \
}

#define AT_HOST_LOOP(statement) { \
  int max = net_max(), at; \
  for (at = net_min(); at < max; at++) { \
    statement; \
  } \
}

void report_close(void) {
  static char buf[1024];
  static char name[81];
  int len_hosts;
#define HOST	"Host"

  if (reportwide) { // get the longest hostname
    len_hosts = strlen(HOST);
    AT_HOST_LOOP(
      int nlen;
      if ((nlen = snprint_addr(name, sizeof(name), &host[at].addr)))
        if (len_hosts < nlen)
          len_hosts = nlen;
    );
    if (len_hosts > sizeof(buf))
      len_hosts = sizeof(buf);
  } else
    len_hosts = 32;

  int l0 = 4;	// 2d._
  int l1 = l0 + len_hosts;
  int len = l0;
  memset(buf, ' ', sizeof(buf));
  buf[sizeof(buf) - 1] = 0;
#ifdef IPINFO
  if (ii_ready()) {
    char *ii = ii_getheader();
    if (ii) {
      int di = ii_getwidth();
      if (di > (sizeof(buf) - l0))
        di = sizeof(buf) - l0;
      memcpy(buf + l0, ii, di);
      len += di;
    }
  }
#endif
  int lh = strlen(HOST);
  memcpy(buf + len, HOST, lh);
  len += lh;
  if (!reportwide)
    len = len_hosts;
  if (len < l1)
    len = l1;

  char fmt[16];
  ACTIVE_FLD_LOOP(
    snprintf(fmt, sizeof(fmt), "%%%ds", data_fields[j].length);
    snprintf(buf + len, sizeof(buf), fmt, data_fields[j].title);
    len += data_fields[j].length;
  );

  AT_HOST_LOOP(
    ip_t *addr = &host[at].addr;
    struct mplslen *mpls = &host[at].mpls;
    snprint_addr(name, sizeof(name), addr);

#ifdef IPINFO
    if (ii_ready()) {
      snprintf(fmt, sizeof(fmt), "%%2d. %%s%%-%ds", len_hosts);
      snprintf(buf, sizeof(buf), fmt, at+1, fmt_ipinfo(addr), name);
    } else {
#endif
    snprintf(fmt, sizeof(fmt), "%%2d. %%-%ds", len_hosts);
    snprintf(buf, sizeof(buf), fmt, at+1, name);
#ifdef IPINFO
    }
#endif

    len = reportwide ? strlen(buf) : l1;
#define REPORT_FLD1(factor) { snprintf(buf + len, sizeof(buf) - len, data_fields[j].format, net_elem(at, data_fields[j].key) factor); }
    ACTIVE_FLD_LOOP(
      /* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
      if (index(data_fields[j].format, 'f'))
        REPORT_FLD1(/1000.0)
      else
        REPORT_FLD1();
      len += data_fields[j].length;
    );

    /* This feature shows 'loadbalances' on routes */

    /* z is starting at 1 because addrs[0] is the same that addr */
    int z;
    for (z = 1; z < MAXPATH ; z++) {
      ip_t *addr2 = &(host[at].addrs[z]);
      struct mplslen *mplss = &(host[at].mplss[z]);
      if (!unaddrcmp(addr2))
        break;
      int found = 0;
      int w;
      for (w = 0; w < z; w++)
        /* Ok... checking if there are ips repeated on same hop */
        if (!addrcmp(addr2, &(host[at].addrs[w]))) {
           found = 1;
           break;
        }

      if (!found) {
        if (mpls->labels && z == 1 && enablempls)
          print_mpls(mpls);
        printf("    ");	// 2d._
#ifdef IPINFO
        if (ii_ready())
          printf("%s", fmt_ipinfo(addr2));
#endif
        snprint_addr(name, sizeof(name), addr2);
        printf("%s\n", name);
        if (enablempls)
          print_mpls(mplss);
      }
    }

    /* No multipath */
    if (mpls->labels && z == 1 && enablempls)
      print_mpls(mpls);
  )
}

void txt_close(void) {
  report_close();
}

void xml_close(void) {
  int i, j, at, max;
  ip_t *addr;
  char name[81];

  printf("<MTR SRC=%s DST=%s", LocalHostname, Hostname);
  printf(" TOS=0x%X", tos);
  if(cpacketsize >= 0) {
    printf(" PSIZE=%d", cpacketsize);
  } else {
    printf(" PSIZE=rand(%d-%d)",MINPACKET, -cpacketsize);
  }
  if( bitpattern>=0 ) {
    printf(" BITPATTERN=0x%02X", (unsigned char)(bitpattern));
  } else {
    printf(" BITPATTERN=rand(0x00-FF)");
  }
  printf(" TESTS=%d>\n", MaxPing);

  max = net_max();
  at  = net_min();
  for(; at < max; at++) {
    addr = &host[at].addr;
    snprint_addr(name, sizeof(name), addr);

    printf("    <HUB COUNT=%d HOST=%s>\n", at+1, name);
    for( i=0; i<MAXFLD; i++ ) {
      j = fld_index[fld_active[i]];
      if (j < 0) continue;

      strcpy(name, "        <%s>");
      strcat(name, data_fields[j].format);
      strcat(name, "</%s>\n");
#define REPORT_FLD2(factor) { printf(name, data_fields[j].title, net_elem(at, data_fields[j].key) factor, data_fields[j].title ); }
      /* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
      if (index(data_fields[j].format, 'f'))
        REPORT_FLD2(/1000.0)
      else
        REPORT_FLD2();
    }
    printf("    </HUB>\n");
  }
  printf("</MTR>\n");
}

void csv_close(time_t now) {
  int i, j;
  for (i = 0; i < MAXFLD; i++) {
    j = fld_index[fld_active[i]];
    if (j < 0)
      continue;
  }

  int max = net_max();
  int at = net_min();
  for (; at < max; at++) {
    ip_t *addr = &host[at].addr;
    int last = host[at].last;

    char name[81];
    snprint_addr(name, sizeof(name), addr);

#ifdef IPINFO
    if (ii_ready())
      printf("MTR.%s;%lld;%s;%s;%d;%s;%s;%d", MTR_VERSION, (long long)now, "OK", Hostname, at+1, name, fmt_ipinfo(addr), last);
    else
#endif
      printf("MTR.%s;%lld;%s;%s;%d;%s;%d", MTR_VERSION, (long long)now, "OK", Hostname, at+1, name, last);

    for (i = 0; i < MAXFLD; i++) {
      j = fld_index[fld_active[j]];
      if (j < 0)
        continue;

      /* 1000.0 is a temporay hack for stats usec to ms, impacted net_loss. */
      if (index(data_fields[j].format, 'f'))
        printf(", %.2f", net_elem(at, data_fields[j].key) / 1000.0);
      else
        printf(", %d", net_elem(at, data_fields[j].key));
    }
    printf("\n");
  }
}

