#ifndef LINUX_EXTERR_H
#define LINUX_EXTERR_H

#include "netmisc.h"

void sockrecverr(int sock, const struct timespec *recv_at, const void *remote); // NONNULL(2, 3)
void ee_settings(enum IPV6_ENDIS ip6, int proto, uint maxseq);


#endif
