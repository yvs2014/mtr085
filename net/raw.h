#ifndef RAW_H
#define RAW_H

#include <gen.h>

#define RECVSOCK recvsock
#define SENDSOCK sendsock

#define IPHSZ_IN_REPLY 20

typedef bool (*ping_fn)(int at);

void close_sock46(void);
int get_valid_seq(const _icmphdr *icmp) NONNULL(1);

extern int recvsock;
extern int sendsock;
extern ping_fn ping_icmp;
extern ping_fn ping_udp;

#endif
