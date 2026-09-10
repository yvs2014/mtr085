#ifndef USER_H
#define USER_H

#include <gen.h>

#define RECVSOCK usersock
#define SENDSOCK usersock

#define IPHSZ_IN_REPLY 0

typedef bool (*ping_fn)(int at);

void close_sock46(void);

extern int usersock;
extern ping_fn ping_icmp;
extern ping_fn ping_udp;

#endif
