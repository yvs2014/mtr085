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

/*
    Non-blocking DNS portion --
    Copyright (C) 1998 by Simon Kirby <sim@neato.org>
    Released under GPL, as above.
*/

#include "config.h"

#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __APPLE__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif

#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <search.h>
#include <errno.h>
#include <time.h>

#include "mtr.h"
#include "dns.h"
#include "net.h"

#ifdef ENABLE_IPV6
#ifdef __GLIBC__
#define NSSOCKADDR6(i) (myres._u._ext.nsaddrs[i])
#else
#define NSSOCKADDR6(i) (&(myres._u._ext.ext->nsaddrs[i].sin6))
#endif
#endif

#ifdef LOG_DNS
#include <syslog.h>
#define DNSLOG_MSG(x)	{ syslog x ; }
#define DNSLOG_ERR(x)	{ syslog x ; return; }
#else
#define DNSLOG_MSG(x)	{}
#define DNSLOG_ERR(x)	{ return; }
#endif

struct resolve {
  char *hostname;
  ip_t ip;
};

static int init;
int resfd;
#ifdef ENABLE_IPV6
int resfd6;
#endif

#ifdef ENABLE_IPV6
struct sockaddr_storage from_sastruct;
struct sockaddr_in6 * from6 = (struct sockaddr_in6 *) &from_sastruct;
#else
struct sockaddr_in from_sastruct;
#endif
struct sockaddr_in * from4 = (struct sockaddr_in *) &from_sastruct;
struct sockaddr * from = (struct sockaddr *) &from_sastruct;

char lookup_key[MAXDNAME];

#define myres _res
#ifdef NEED_RES_STATE_EXT
/* __res_state_ext is missing on many (most?) BSD systems */
struct __res_state_ext {
  union res_sockaddr_union nsaddrs[MAXNS];
  struct sort_list {
    int  af;
    union {
      struct in_addr  ina;
      struct in6_addr in6a;
    } addr, mask;
  } sort_list[MAXRESOLVSORT];
  char nsuffix[64];
  char nsuffix2[64];
};
#endif

int dns_waitfd(int family) {
#ifdef ENABLE_IPV6
  if (family == AF_INET6)
    return resfd6;
  else
#endif
    return resfd;
}

void dns_open(void) {
  if (!enable_dns || init)
    return;
  DNSLOG_MSG((MTR_SYSLOG, "dns init"));

  if (!hinit) {
    if (!hcreate(maxTTL * 4)) {
      perror("hcreate()");
      return;
    }
    hinit = 1;
  }

  res_init();
  if (!myres.nscount) {
    perror("No nameservers defined");
    return;
  }
  myres.options |= RES_RECURSE | RES_DEFNAMES | RES_DNSRCH;
  int option = 1;

  if ((resfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    perror("dns_open(): socket4()");
  else
	if (setsockopt(resfd, SOL_SOCKET, SO_BROADCAST, (char *)&option, sizeof(option)) < 0)
      perror("dns_open(): setsockopt4()");
#ifdef ENABLE_IPV6
  if ((resfd6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
//    perror("dns_open(): socket6()");
  {}
  else
	if (setsockopt(resfd6, SOL_SOCKET, SO_BROADCAST, (char *)&option, sizeof(option)) < 0)
      perror("dns_open(): setsockopt6()");
#endif

  if ((resfd >= 0)
#ifdef ENABLE_IPV6
   || (resfd6 >= 0)
#endif
     )
    init = 1;
  else
    fprintf(stderr, "dns_open() failed: out of sockets\n");

  return;
}

void dns_close(void) {
  if (resfd)
    close(resfd);
#ifdef ENABLE_IPV6
  if (resfd6)
    close(resfd6);
#endif
  if (hinit) {
    hdestroy();
    hinit = 0;
  }
  init = 0;
}

#ifdef ENABLE_IPV6
/* Returns an ip6.arpa character string. */
void addr2ip6arpa( ip_t * ip, char * buf ) {
  unsigned char * p = (unsigned char *) ip;
  char * b = buf;
  int i;

  for ( i = sizeof (struct in6_addr) - 1; i >= 0; i-- ) {
        sprintf( b, "%x.%x.", p[i] % 16, p[i] >> 4 );
        b += 4;
  }
  sprintf( b, "ip6.arpa" );
  return;
}
#endif

char* set_lookup_key(ip_t *ip) {
#ifdef ENABLE_IPV6
  if (af == AF_INET6)
    addr2ip6arpa(ip, lookup_key);
  else /* if (af == AF_INET) */
#endif
    sprintf(lookup_key, "%u.%u.%u.%u.in-addr.arpa", ((byte *)ip)[3], ((byte *)ip)[2], ((byte *)ip)[1], ((byte *)ip)[0]);
  return lookup_key;
}

void sendrequest(struct resolve *rp) {
  set_lookup_key(&(rp->ip));
  word id = str2hash(lookup_key);
  DNSLOG_MSG((MTR_SYSLOG, "Send \"%s\" (id=%d)", lookup_key, id));

  unsigned char buf[PACKETSZ];
  int r = res_mkquery(QUERY, lookup_key, C_IN, T_PTR, NULL, 0, NULL, buf, sizeof(buf));
  if (r < 0)
    DNSLOG_ERR((MTR_SYSLOG, "Query too large"));

  HEADER *hp = (HEADER*)buf;
  hp->id = id;	/* htons() deliberately left out (redundant) */
  int re = 0, i;
  for (i = 0; i < myres.nscount; i++) {

#ifdef LOG_DNS
    char straddr[INET6_ADDRSTRLEN] = {0};
    void* nsa = NULL;
    if (myres.nsaddr_list[i].sin_family == AF_INET)
      nsa = &(myres.nsaddr_list[i].sin_addr);
#ifdef ENABLE_IPV6
    else if (myres.nsaddr_list[i].sin_family == AF_INET6)
      nsa = &(NSSOCKADDR6(i)->sin6_addr);
#endif
    if (nsa)
      inet_ntop(myres.nsaddr_list[i].sin_family, nsa, straddr, sizeof(straddr));
#endif

    if (myres.nsaddr_list[i].sin_family == AF_INET)
      re = sendto(resfd, buf, r, 0, (struct sockaddr *)&myres.nsaddr_list[i], sizeof(struct sockaddr));
#ifdef ENABLE_IPV6
    else if (myres.nsaddr_list[i].sin_family == AF_INET6)
      re = sendto(resfd6, buf, r, 0, (struct sockaddr *)NSSOCKADDR6(i), sizeof(struct sockaddr_in6));
#endif
    if (re < 0)
      perror("sendrequest(): sendto()");

#ifdef LOG_DNS
    if ((myres.nsaddr_list[i].sin_family == AF_INET) || (myres.nsaddr_list[i].sin_family == AF_INET6))
      DNSLOG_MSG((MTR_SYSLOG, "Request id=%d to %s %s", id, straddr, (re < 0) ? "failed" : "was sent"));
#endif
  }
}

struct resolve *hfind_res(word id) {
  word ids[2] = { id, 0 };
  ENTRY item = { (void*)ids };
  ENTRY *hr = hsearch(item, FIND);
  return ((hr) ? hr->data : hr);
}

const char *dns_lookup(ip_t *ip) {
  if (!enable_dns)
    return NULL;

  word id = str2hash(set_lookup_key(ip));
  struct resolve *rp = hfind_res(id);
  if (rp)
    return rp->hostname;

  rp = malloc(sizeof(*rp));
  if (!rp) {
    perror("dns_lookup(): malloc()");
    return NULL;
  }
  DNSLOG_MSG((MTR_SYSLOG, "> Add hash record (id=%d) for %s", id, strlongip(ip)));
  addrcpy(&(rp->ip), ip);
  rp->hostname = NULL;

  ENTRY item;
  word ids[2] = { id, 0 };
  if (!(item.key = malloc(sizeof(ids)))) {
    perror("dns_lookup(): malloc()");
    free(rp);
    return NULL;
  }
  memcpy(item.key, ids, sizeof(ids));
  item.data = rp;

  if (!hsearch(item, ENTER)) {
    perror("dns_lookup(): hsearch(ENTER)");
    DNSLOG_MSG((MTR_SYSLOG, "hsearch(ENTER, key=%s) failed", lookup_key));
    free(item.key);
    free(rp);
    return NULL;
  }

  sendrequest(rp);
  return NULL;
}

void parserespacket(unsigned char *buf, int l) {
  static char answer[MAXDNAME];

  if (l < (int) sizeof(HEADER))
    DNSLOG_ERR((MTR_SYSLOG, "Packet smaller than standard header size"));
  if (l == (int) sizeof(HEADER))
    DNSLOG_ERR((MTR_SYSLOG, "Packet has empty body"));
  HEADER *hp = (HEADER*)buf;

  DNSLOG_MSG((MTR_SYSLOG, "Got %d bytes, id=%d", l, hp->id));
  /* Convert data to host byte order */
  /* hp->id does not need to be redundantly byte-order flipped, it is only echoed by nameserver */
  struct resolve *rp = hfind_res(hp->id);
  if (!rp)
    DNSLOG_ERR((MTR_SYSLOG, "Got unknown response (id=%d)", hp->id));
  if (rp->hostname)
    DNSLOG_ERR((MTR_SYSLOG, "Duplicated response for %s? (id=%d, hostname=%s)", strlongip(&(rp->ip)), hp->id, rp->hostname));

  hp->qdcount = ntohs(hp->qdcount);
  hp->ancount = ntohs(hp->ancount);
  hp->nscount = ntohs(hp->nscount);
  hp->arcount = ntohs(hp->arcount);
  if (hp->tc)	/* Packet truncated */
    DNSLOG_ERR((MTR_SYSLOG, "Nameserver packet truncated"));
  if (!hp->qr)	/* Not a reply */
    DNSLOG_ERR((MTR_SYSLOG, "Query packet received on nameserver communication socket"));
  if (hp->opcode)	/* Not opcode 0 (standard query) */
    DNSLOG_ERR((MTR_SYSLOG, "Invalid opcode in response packet"));
  unsigned char *eob = buf + l;
  unsigned char *c = buf + sizeof(HEADER);

  if (hp->rcode != NOERROR) {
#ifdef LOG_DNS
    if (hp->rcode == NXDOMAIN)
      DNSLOG_MSG((MTR_SYSLOG, "Host %s not found", strlongip(&(rp->ip))))
	else
      DNSLOG_MSG((MTR_SYSLOG, "Received error response %u", hp->rcode));
#endif
	return;
  }
  if (!(hp->ancount))
    DNSLOG_ERR((MTR_SYSLOG, "No error returned but no answers given"));

  DNSLOG_MSG((MTR_SYSLOG, "Received nameserver reply (qd:%u an:%u ns:%u ar:%u)", hp->qdcount, hp->ancount, hp->nscount, hp->arcount));
  if (hp->qdcount != 1)
    DNSLOG_ERR((MTR_SYSLOG, "Reply does not contain one query"));
  if (c > eob)
    DNSLOG_ERR((MTR_SYSLOG, "Reply too short"));

  set_lookup_key(&(rp->ip));
  *answer = 0;

  int r = dn_expand(buf, buf + l, c, answer, sizeof(answer));
  if (r < 0)
    DNSLOG_ERR((MTR_SYSLOG, "dn_expand() failed while expanding query domain"));
  answer[strlen(lookup_key)] = 0;
  if (strcasecmp(lookup_key, answer))
    DNSLOG_ERR((MTR_SYSLOG, "Unknown query packet dropped (\"%s\" does not match \"%s\")", lookup_key, answer));
  DNSLOG_MSG((MTR_SYSLOG, "Queried \"%s\"", answer));
  c += r;
  if (c + 4 > eob)
    DNSLOG_ERR((MTR_SYSLOG, "Query resource record truncated"));
  int type, size;
  GETSHORT(type, c);
  if (type != T_PTR)
    DNSLOG_ERR((MTR_SYSLOG, "Received unimplemented query type %u", type))
  c += INT16SZ;	// skip class

  int i;
  for (i = hp->ancount + hp->nscount + hp->arcount; i; i--) {
    if (c > eob)
      DNSLOG_ERR((MTR_SYSLOG, "Packet does not contain all specified resouce records"));
    memset(answer, 0, sizeof(answer));
    r = dn_expand(buf, buf + l, c, answer, sizeof(answer) - 1);
    if (r < 0)
      DNSLOG_ERR((MTR_SYSLOG, "dn_expand() failed while expanding answer domain"));
//    answer[strlen(lookup_key)] = 0;
    c += r;
    if (c + 10 > eob)
      DNSLOG_ERR((MTR_SYSLOG, "Resource record truncated"));
    GETSHORT(type, c);
    c += INT16SZ;	// skip class
	c += INT32SZ;	// skip ttl
    GETSHORT(size, c);
    if (!size)
      DNSLOG_ERR((MTR_SYSLOG, "Zero size rdata"));
    if (c + size > eob)
      DNSLOG_ERR((MTR_SYSLOG, "Specified rdata length exceeds packet size"));
    if (type != T_PTR) {
      DNSLOG_MSG((MTR_SYSLOG, "Ignoring resource type %u", type));
      c += size;
	  continue;
	}
    if (strncasecmp(lookup_key, answer, sizeof(answer))) {
      DNSLOG_MSG((MTR_SYSLOG, "No match for \"%s\": \"%s\"", lookup_key, answer));
      c += size;
	  continue;
	}

    memset(answer, 0, sizeof(answer));
    r = dn_expand(buf, buf + l, c, answer, sizeof(answer) - 1);
    if (r < 0)
      DNSLOG_ERR((MTR_SYSLOG, "dn_expand() failed while expanding domain in rdata"));
    int l = strnlen(answer, sizeof(answer));
    DNSLOG_MSG((MTR_SYSLOG, "Answer[%d]: \"%s\"[%d]", r, answer, l));
//    if (l > MAXHOSTNAMELEN) {
//      DNSLOG_ERR((MTR_SYSLOG, "Ignoring reply: hostname too long: %d > %d", l, MAXHOSTNAMELEN));
//      return;
//    }

    rp->hostname = malloc(l + 1);
    if (!rp->hostname) {
      perror("parserespacket(): malloc()");
      return;
    }
    strncpy(rp->hostname, answer, l + 1);
    c += size;
  }
}

void dns_ack(int fd, int family) {
  static struct in_addr localhost4 = { INADDR_LOOPBACK };
#ifdef ENABLE_IPV6
  static struct in6_addr localhost6 = IN6ADDR_LOOPBACK_INIT;
#endif
  static socklen_t fromlen = sizeof(from_sastruct);
  static unsigned char buf[PACKETSZ];

  int r = recvfrom(fd, buf, sizeof(buf), 0, from, &fromlen);
  if (r <= 0) {
    perror("dns_ack(): recvfrom()");
    return;
  }

  /* Check to see if this server is actually one we sent to */
  int i;
#ifdef ENABLE_IPV6
  if (family == AF_INET6) {
    int lh = addr6cmp(&(from6->sin6_addr), &localhost6);
    for (i = 0; i < myres.nscount; i++) {
      if (!addr6cmp(&(NSSOCKADDR6(i)->sin6_addr), &(from6->sin6_addr)))
        break;
      if (!lh)
        if (!addr6cmp(&(NSSOCKADDR6(i)->sin6_addr), &unspec_addr))
          break;
    }
  } else /* if (family == AF_INET) */
#endif
  {
    int lh = addr4cmp(&(from4->sin_addr), &localhost4);
    for (i = 0; i < myres.nscount; i++) {
      if (!addr4cmp(&(myres.nsaddr_list[i].sin_addr), &(from4->sin_addr)))
        break;
      if (!lh)
        if (!addr4cmp(&(myres.nsaddr_list[i].sin_addr), &unspec_addr))
          break;
    }
  }

  if (i != myres.nscount)
    parserespacket(buf, r);
#ifdef LOG_DNS
  else {
    if (af == AF_INET)
      DNSLOG_MSG((MTR_SYSLOG, "Received reply from unknown source: %s", inet_ntop(af, &(from4->sin_addr), lookup_key, sizeof(lookup_key))))
#ifdef ENABLE_IPV6
    else /* if (af == AF_INET6) */
      DNSLOG_MSG((MTR_SYSLOG, "Received reply from unknown source: %s", inet_ntop(af, &(from6->sin6_addr), lookup_key, sizeof(lookup_key))));
#endif
  }
#endif
}

