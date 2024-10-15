
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "graphcairo.h"

#include "mtr-curses.h"
#include "mtr-poll.h"
#include "net.h"
#include "display.h"
#ifdef ENABLE_DNS
#include "dns.h"
#endif
#ifdef WITH_IPINFO
#include "ipinfo.h"
#endif
#include "aux.h"

#define GC_ARGS_SEP	','
#define GC_ARGS_MAX	5

#ifndef STARTSTAT
#define STARTSTAT	30
#endif

#ifdef WITH_IPINFO
#define HOSTSTAT_LEN (3 * STARTSTAT + SAVED_PINGS)  // hostinfo + statistics
#else
#define HOSTSTAT_LEN (STARTSTAT + SAVED_PINGS)      // hostname + statistics
#endif

#define	NUMHOSTS	10	// net.c static numhosts = 10

static int timeout;
static struct timespec lasttime;

static cr_params_t params;
#define ARG_GRAPH_TYPE	0
#define ARG_PERIOD	1
#define ARG_LEGEND	2
#define ARG_MULTIPATH	3
#define ARG_JITTER_GRAPH	4

static int args[GC_ARGS_MAX];
static int *data;
static int curses_cols;
static int hostinfo_max;
static char legend_header[HOSTSTAT_LEN];

bool gc_open(void) {
  size_t data_sz = maxTTL * sizeof(int);
  data = malloc(data_sz);
  if (!data) {
    WARN("malloc(%zd)", data_sz);
    return false;
  }
  memset(data, -1, data_sz);
  timeout = POS_ROUND(wait_time * MIL);
  clock_gettime(CLOCK_MONOTONIC, &lasttime);
  params.graph_type = (args[ARG_GRAPH_TYPE] > 0) ? args[ARG_GRAPH_TYPE] : 0;
  params.period = (args[ARG_PERIOD] > 0) ? args[ARG_PERIOD] : 0;
  params.enable_legend = args[ARG_LEGEND] ? true : false;
  params.enable_multipath = (args[ARG_MULTIPATH] > 0) ? true : false;
  params.jitter_graph = (args[ARG_JITTER_GRAPH] > 0);
  params.cols_max = SAVED_PINGS;
  params.path_max = MAXPATH;
  params.label_max = MAXLABELS;
  if (!cr_open(&params))
    return false;
  if (params.enable_legend) {
    if (params.jitter_graph)
      onoff_jitter();
    mc_statf_title(legend_header, sizeof(legend_header));
    curses_cols = cr_recalc(hostinfo_max);
    mc_init();
  }
  return true;
}

void gc_close(void) { if (data) free(data); cr_close(); }

bool gc_parsearg(char* arg) {
  int i = 0;
  if (arg) {
    char *n, *p, *h = strdup(arg);
    if (!h) {
      WARN("strdup()");
      return false;
    }
    for (p = h; (n = strchr(p, GC_ARGS_SEP)) && (i < GC_ARGS_MAX); i++, p = n) {
      *n++ = 0;
      args[i] = (*p) ? atoi(p) : -1;
    }
    if (p && (i < GC_ARGS_MAX))
      args[i++] = (*p) ? atoi(p) : -1;
    free(h);
  }
  for (int j = i; j < GC_ARGS_MAX; j++)
    args[j] = -1;
  return true;
}

static int fill_hostinfo(int at, int ndx, char *buf, int sz) {
  int l = 0;
#ifdef WITH_IPINFO
  if (ipinfo_ready())
    l += snprintf(buf, sz, "%.*s", 2 * STARTSTAT, fmt_ipinfo(at, ndx));
#endif
#ifdef ENABLE_DNS
  const char *name = dns_ptr_lookup(at, ndx);
  if (name) {
    if (show_ips) {
      int len = STARTSTAT / 2 - 1;
      l += snprintf(buf + l, sz - l, "%.*s (%.*s)", len, name, len - 1, strlongip(&IP_AT_NDX(at, ndx)));
    } else
      l += snprintf(buf + l, sz - l, "%.*s", STARTSTAT, name);
  } else
#endif
    l += snprintf(buf + l, sz - l, "%.*s", STARTSTAT, strlongip(&IP_AT_NDX(at, ndx)));
  if (((at + 1) >= display_offset) && (l > hostinfo_max))
    hostinfo_max = l;
  return l;
}


int gc_keyaction(void) {
  int c = cr_dispatch_event();

  if (c == ACTION_RESIZE) {
    if (params.enable_legend)
      curses_cols = cr_recalc(hostinfo_max);
    return ActionNone;
  }

  if (params.enable_legend) {
    switch (c) {
      case '+':  // ScrollDown
        GCMSG("%s", "scroll down\n");
        hostinfo_max = 0;
        return ActionScrollDown;
      case '-':  // ScrollUp
        GCMSG("%s", "scroll up\n");
        hostinfo_max = 0;
        return ActionScrollUp;
#ifdef WITH_MPLS
      case 'e':  // MPLS
        GCMSG("%s", "toggle MPLS\n");
        return ActionMPLS;
#endif
      case 'j':  // Latency,Jitter
        GCMSG("%s", "toggle latency/jitter stats\n");
        onoff_jitter();
        mc_statf_title(legend_header, sizeof(legend_header));
        return ActionNone;
#ifdef ENABLE_DNS
      case 'n':  // DNS
        GCMSG("%s", "toggle DNS\n");
        hostinfo_max = 0;
        return ActionDNS;
#endif
#ifdef WITH_IPINFO
      case 'y':  // IP Info
        GCMSG("%s", "switching IP info\n");
        hostinfo_max = 0;
        return ActionII;
      case 'z':  // ASN
        GCMSG("%s", "toggle ASN info\n");
        hostinfo_max = 0;
        return ActionAS;
#endif
	}
  }

  switch (c) {
    case 'p':  // Pause,Resume
      GCMSG("%s", "pause/resume pressed");
      return ActionPauseResume;
    case  3 :  // ^C
    case 'q':  // Quit
      GCMSG("%s", "quit\n");
      return ActionQuit;
    case 'r':  // Reset
      GCMSG("%s", "net reset\n");
      cr_net_reset(0);
      return ActionReset;
    case 't':  // TCP on/off
      GCMSG("%s", "toggle TCP pings\n");
      return ActionTCP;
    case 'u':  // UDP on/off
      GCMSG("%s", "toggle UDP pings\n");
      return ActionUDP;
  }
  return ActionNone;
}

#ifdef WITH_MPLS
static void gc_print_mpls(int i, int d, const mpls_data_t *m, char *buf, int sz) {
  if (!m)
    return;
  for (int j = 0; j < m->n; j++) {
    snprintf(buf, sz, "%s", mpls2str(&(m->label[i]), 0));
    cr_print_host(i, d, buf, NULL);
  }
}
#endif

void gc_redraw(void) {
  static char glinebuf[HOSTSTAT_LEN];
  static long prevnum;
  if (prevnum >= numpings)
    return;
  prevnum = numpings;

  int min = net_min();
  int max = net_max();
  int hops = max - min /* + 1 */;
  if (!hops)
    hops++;
  cr_set_hops(hops, min);

  if (params.enable_legend) {
    static int hi_max;
    if (!hostinfo_max)
      hi_max = 0;
    if (hostinfo_max > hi_max) {
      hi_max = hostinfo_max;
      curses_cols = cr_recalc(hostinfo_max);
    }
    cr_init_legend();
    cr_print_legend_header(legend_header);
  }

  for (int i = 0, at = min; i < hops; i++, at++) {
    t_ipaddr *addr = &CURRENT_IP(at);

    if (addr_exist(addr)) {
      int saved_ndx = SAVED_PINGS - 2;
      if (params.jitter_graph) {
        // jitter: "tN - tN-1"
        if ((host[at].saved[saved_ndx] < 0) || (host[at].saved[saved_ndx - 1] < 0))	// unsent, unknown, etc.
          data[i] = -1;
        else {
          int saved_jttr = host[at].saved[saved_ndx] - host[at].saved[saved_ndx - 1];
          data[i] = (saved_jttr < 0) ? -saved_jttr : saved_jttr;
        }
      } else
        data[i] = (host[at].saved[saved_ndx] >= 0) ? host[at].saved[saved_ndx] : -1;

      if (params.enable_legend) {
        cr_print_hop(i); // #. hop
        int l = fill_hostinfo(at, host[at].current, glinebuf, sizeof(glinebuf)); // hostinfo
        l += 1; // step over 0
        mc_print_at(at, glinebuf + l, sizeof(glinebuf) - l); // statistics
        cr_print_host(i, data[i], glinebuf, glinebuf + l);   // host+stat
#ifdef WITH_MPLS
        if (enable_mpls) // mpls
          gc_print_mpls(i, data[i], &CURRENT_MPLS(at), glinebuf, sizeof(glinebuf));
#endif
        if (params.enable_multipath) {                       // multipath
          for (int j = 0; j < MAXPATH; j++) {
            if (j != host[at].current) {
              t_ipaddr *ip = &IP_AT_NDX(at, j);
              if (!addr_exist(ip))
                break;
              fill_hostinfo(at, j, glinebuf, sizeof(glinebuf));
              cr_print_host(i, data[i], glinebuf, NULL);
#ifdef WITH_MPLS
              if (enable_mpls) // multipath+mpls
                gc_print_mpls(i, data[i], &MPLS_AT_NDX(at, j), glinebuf, sizeof(glinebuf));
#endif
            }
          }
        }
      }
    } else if (params.enable_legend) { // empty hop
      cr_print_hop(i);
      cr_print_host(i, 0, NULL, NULL);
    }
  } // end-of-for

  cr_redraw(data);
  if (hops)
    timeout = POS_ROUND(((wait_time * hops) / NUMHOSTS) * MIL);
}

