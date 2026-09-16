#ifndef RAW_H
#define RAW_H

#include <gen.h>

#define RECVSOCK recvsock
#define SENDSOCK sendsock
extern int recvsock;
extern int sendsock;

#define IPHSZ_IN_REPLY 20
int get_valid_seq(const _icmphdr *icmp) NONNULL(1);

#endif
