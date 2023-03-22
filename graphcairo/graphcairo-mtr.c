
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

#include "config.h"

#ifdef UNICODE
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#endif

#include "mtr.h"
#include "mtr-curses.h"
#include "select.h"
#include "net.h"
#include "dns.h"
#ifdef IPINFO
#include "ipinfo.h"
#endif
#include "display.h"
#include "graphcairo.h"

#define GC_ARGS_SEP	','
#define GC_ARGS_MAX	5

#ifdef UNICODE
#define U_FACTOR	sizeof(wchar_t)
#else
#define U_FACTOR	1
#endif

#ifndef STARTSTAT
#define STARTSTAT	30
#endif

#ifdef IPINFO
#define HOSTSTAT_LEN	(3 * STARTSTAT + U_FACTOR * SAVED_PINGS)	// hostinfo + statistics
#else
#define HOSTSTAT_LEN	(STARTSTAT + U_FACTOR * SAVED_PINGS)		// hostname + statistics
#endif

#define	NUMHOSTS	10	// net.c static numhosts = 10

static int timeout;
static struct timeval lasttime;

static bool paused = false;
static cr_params_t params;
#define ARG_GRAPH_TYPE	0
#define ARG_PERIOD	1
#define ARG_LEGEND	2
#define ARG_MULTIPATH	3
#define ARG_JITTER_GRAPH	4

static int args[GC_ARGS_MAX];
static int *data;
static int num_pings;
static int curses_cols;
static int hostinfo_max;
static char buf[HOSTSTAT_LEN];

enum {
	LEGEND_HEADER_STATIC,
	LEGEND_HEADER,
	LEGEND_FOOTER
};
#define LEGEND_HD_NO    3
static char legend_hd[LEGEND_HD_NO][HOSTSTAT_LEN];

int gc_open(void) {
	if ((data = malloc(maxTTL * sizeof(int))))
		memset(data, -1, maxTTL * sizeof(int));
	else {
		fprintf(stderr, "gc_open: malloc() failed\n");
		return 0;
	}

	timeout = POS_ROUND(wait_time * USECONDS);
	gettimeofday(&lasttime, NULL);

	params.graph_type = (args[ARG_GRAPH_TYPE] > 0) ? args[ARG_GRAPH_TYPE] : 0;
	params.period = (args[ARG_PERIOD] > 0) ? args[ARG_PERIOD] : 0;
	params.enable_legend = args[ARG_LEGEND] ? true : false;
	params.enable_multipath = (args[ARG_MULTIPATH] > 0) ? true : false;
	params.jitter_graph = (args[ARG_JITTER_GRAPH] > 0);
	params.cols_max = SAVED_PINGS;
	params.path_max = MAXPATH;
	params.label_max = MAXLABELS;

	if (!cr_open(&params))
		return 0;

	if (params.enable_legend) {
		if (params.jitter_graph)
			strcpy((char*)fld_active, FLD_ACTIVE_JITTER);
		mtr_curses_data_fields(legend_hd[LEGEND_HEADER_STATIC]);
		curses_cols = cr_recalc(hostinfo_max);
		mtr_curses_init();
	}

	return 1;
}

void gc_close(void) {
	free(data);
	cr_close();
}

void gc_parsearg(char* arg) {
	int i = 0;
	if (arg) {
		char *n, *p, *h = strdup(arg);
		for (p = h; (n = strchr(p, GC_ARGS_SEP)) && (i < GC_ARGS_MAX); i++, p = n) {
			*n++ = 0;
			args[i] = (*p) ? atoi(p) : -1;
		}
		if (p && (i < GC_ARGS_MAX))
			args[i++] = (*p) ? atoi(p) : -1;
		free(h);
	}

	int j;
	for (j = i; j < GC_ARGS_MAX; j++)
		args[j] = -1;
}

static void fill_hostinfo(int at, ip_t *addr) {
	int l, len = 0;
	char *p = buf;
	int sz;
#ifdef IPINFO
	if (ii_ready()) {
		sz = 2 * STARTSTAT;
		l = snprintf(p, sz, "%s", fmt_ipinfo(addr));
		if (l < 0)
			sz = 0;
		else if (l < sz)
			sz = l;
		else
			sz -= 1;
		len += sz;
		p += sz;
	}
#endif
	sz = STARTSTAT;
	const char *name = dns_lookup(addr);
	if (name) {
		l = snprintf(p, sz, "%s", name);
		if (show_ips)
			l += snprintf(p + l, sz - l, " (%s)", strlongip(addr));
	} else
		l = snprintf(p, sz, "%s", strlongip(addr));

	if (l < 0)
		sz = 0;
	else if (l < sz)
		sz = l;
	else
		sz -= 1;
	len += sz;

	if ((at + 1) >= display_offset)
		if (len > hostinfo_max)
			hostinfo_max = len;
}

static void pr_lastd(void) {
	if (curses_mode)
		sprintf(legend_hd[LEGEND_HEADER], "Last %d pings", curses_cols);
}

static void gc_keyaction(int c) {
	if (!c)
		return;

	if (c == ACTION_RESIZE) {
		if (params.enable_legend) {
			curses_cols = cr_recalc(hostinfo_max);
			pr_lastd();
		}
		return;
	}

	if (params.enable_legend) {
		switch (c) {
			case '+': {	// ScrollDown
				int hops = net_max() - net_min();
				display_offset += 5;
				if (display_offset >= hops)
					display_offset = hops - 1;
				hostinfo_max = 0;
				GCDEBUG_MSG(("display_offset=%d\n", display_offset));
			} break;
			case '-': {	// ScrollUp
				int rest = display_offset % 5;
				if (rest)
					display_offset -= rest;
				else
					display_offset -= 5;
				if (display_offset < 0)
					display_offset = 0;
				hostinfo_max = 0;
				GCDEBUG_MSG(("display_offset=%d\n", display_offset));
			} break;
#ifdef IPINFO
			case 'y':	// IP Info
				ii_action(ActionII);
				hostinfo_max = 0;
				GCDEBUG_MSG(("switching ip info\n"));
				break;
			case 'Y':	// on Google Maps
				ii_action(ActionII_Map);
				hostinfo_max = 0;
				GCDEBUG_MSG(("show on google maps\n"));
				break;
#endif

		}
		switch (tolower(c)) {
			case 'd':	// Display
				curses_mode = (curses_mode + 1) % curses_mode_max;
				if (curses_mode)
					curses_cols = cr_recalc(hostinfo_max);
				pr_lastd();
				GCDEBUG_MSG(("curses_mode=%d\n", curses_mode));
				break;
			case 'e':	// MPLS
				enable_mpls = !enable_mpls;
				GCDEBUG_MSG(("enable_mpls=%d\n", enable_mpls));
				break;
			case 'j':
				if (index((char*)fld_active, 'N'))
					strcpy((char*)fld_active, FLD_ACTIVE_JITTER);
				else
					strcpy((char*)fld_active, FLD_ACTIVE_DEFAULT);
				mtr_curses_data_fields(legend_hd[LEGEND_HEADER_STATIC]);
				GCDEBUG_MSG(("toggle latency(default)/jitter stats\n"));
				break;
			case 'n':	// DNS
				enable_dns = !enable_dns;
				hostinfo_max = 0;
				GCDEBUG_MSG(("enable_dns=%d\n", enable_dns));
				break;
#ifdef IPINFO
			case 'z':	// ASN
				ii_action(ActionAS);
				hostinfo_max = 0;
				GCDEBUG_MSG(("toggle asn info\n"));
				break;
#endif
		}
	}

	switch (c) {
		case 'q':	// Quit
			gc_close();
			GCDEBUG_MSG(("bye-bye\n"));
			exit(0);
			break;
		case ' ':	// Resume
			paused = false;
			cr_net_reset(1);
			GCDEBUG_MSG(("...resume\n"));
			break;
	}
	switch (tolower(c)) {
		case 'p':	// Pause
			paused = true;
			GCDEBUG_MSG(("pause...\n"));
			break;
		case 'r':	// Reset
			net_reset();
			cr_net_reset(0);
			num_pings = 0;
			GCDEBUG_MSG(("net reset\n"));
			break;
		case 't':	// TCP on/off
			if (mtrtype == IPPROTO_TCP) {
				mtrtype = IPPROTO_ICMP;
				GCDEBUG_MSG(("icmp_echo packets\n"));
			} else if (net_tcp_init()) {
				mtrtype = IPPROTO_TCP;
				GCDEBUG_MSG(("tcp_syn packets\n"));
			}
			break;
		case 'u':	// UDP on/off
			if (mtrtype == IPPROTO_UDP) {
				mtrtype = IPPROTO_ICMP;
				GCDEBUG_MSG(("icmp_echo packets\n"));
			} else {
				mtrtype = IPPROTO_UDP;
				GCDEBUG_MSG(("udp datagrams\n"));
			}
			break;
	}
}

static void gc_print_mpls(int i, int d, const mpls_data_t *m) {
	if (m) {
		for (int j = 0; j < m->n; j++) {
			sprintf(buf, "%s", mpls2str(&(m->label[i]), 0));
			cr_print_host(i, d, buf, NULL);
		}
	}
}

void gc_redraw(void) {
	gc_keyaction(cr_dispatch_event());
	if (paused)
		return;

	int i, at;
	int min = net_min();
	int max = net_max();
	int hops = max - min /* + 1 */;
	if (!hops)
		hops++;

	cr_set_hops(hops, min);

	struct timeval now, _tv;
	gettimeofday(&now, NULL);
	timersub(&now, &lasttime, &_tv);
	time_t dt = timer2usec(&_tv);
	lasttime = now;

	if (dt < timeout) {
		int pings = host[min].xmit;
		for (at = min + 1; at < (max - 1); at++)
			if (host[at].xmit != pings)
				return;
		if (pings > num_pings)
			num_pings = pings;
		else
			return;
	}

	if (params.enable_legend) {
		static int hi_max;
		if (!hostinfo_max)
			   hi_max = 0;
		if (hostinfo_max > hi_max) {
			hi_max = hostinfo_max;
			curses_cols = cr_recalc(hostinfo_max);
			pr_lastd();
		}
		cr_init_legend();
		cr_print_legend_header(curses_mode ? legend_hd[LEGEND_HEADER] : legend_hd[LEGEND_HEADER_STATIC]);
	}

	for (i = 0, at = min; i < hops; i++, at++) {
		ip_t *addr = &CURRENT_IP(at);

		if (unaddrcmp(addr)) {
			int saved_ndx = SAVED_PINGS - 2;	// waittime ago
			if (params.jitter_graph) {
				// jitter, defined as "tN - tN-1" (net.c)
				if ((host[at].saved[saved_ndx] < 0) || (host[at].saved[saved_ndx - 1] < 0))	// unsent, unknown, etc.
					data[i] = -1;
				else {
					int saved_jttr = host[at].saved[saved_ndx] - host[at].saved[saved_ndx - 1];
					data[i] = (saved_jttr < 0) ? -saved_jttr : saved_jttr;
				}
			} else
				data[i] = (host[at].saved[saved_ndx] >= 0) ? host[at].saved[saved_ndx] : -1;

			if (params.enable_legend) {
				// line+hop
				cr_print_hop(i);

				// hostinfo
				fill_hostinfo(at, addr);

				int stat_pos = strlen(buf) + 1;
				char *stat = buf + stat_pos;
				// statistics
				if (curses_mode) {
					mtr_gen_scale_gc();
					char *pos = stat;
#ifdef UNICODE
					if (curses_mode == 3) {
						int j;
						for (j = SAVED_PINGS - curses_cols; j < SAVED_PINGS; j++) {
							*(wchar_t*)pos = mtr_curses_saved_wch(host[at].saved[j]);
							pos += sizeof(wchar_t);
						}
						*(wchar_t*)pos = L'\0';
					} else
#endif
					{
						int j;
						for (j = SAVED_PINGS - curses_cols; j < SAVED_PINGS; j++)
							*pos++ = mtr_curses_saved_ch(host[at].saved[j]);
						*pos = 0;
					}
				} else
					mtr_fill_data(at, stat, sizeof(buf) - stat_pos);
				cr_print_host(i, data[i], buf, stat);

				// mpls
				if (enable_mpls)
					gc_print_mpls(i, data[i], &CURRENT_MPLS(at));

				// multipath
				if (params.enable_multipath) {
					for (int j = 0; j < MAXPATH; j++) {
						if (j == host[at].current)
							continue; // because already printed
						ip_t *ip = &IP_AT_NDX(at, j);
						if (!unaddrcmp(ip))
							break;
						fill_hostinfo(at, ip);
						cr_print_host(i, data[i], buf, NULL);
						if (enable_mpls)	// multipath+mpls
							gc_print_mpls(i, data[i], &MPLS_AT_NDX(at, j));
					}
				}
			}
		} else	// empty hop
			if (params.enable_legend) {
				cr_print_hop(i);
				cr_print_host(i, 0, NULL, NULL);
			}
	}

	if (params.enable_legend)
		if (curses_mode) {
			mtr_curses_scale_desc(legend_hd[LEGEND_FOOTER]);
			cr_print_legend_footer(legend_hd[LEGEND_FOOTER]);
		}

	cr_redraw(data);

	if (hops)
		timeout = POS_ROUND(((wait_time * hops) / NUMHOSTS) * USECONDS);
}

