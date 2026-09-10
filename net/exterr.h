#ifndef EXTERR_H
#define EXTERR_H

#include "netmisc.h"

void sockrecverr(int sock, const struct timespec *recv_at, const void *remote); // NONNULL(2, 3)
void ee_settings(enum IPV6_ENDIS ip6);

#endif
