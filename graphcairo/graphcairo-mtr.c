
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>

#include "config.h"
#include "mtr.h"
#include "mtr-curses.h"
#include "net.h"
#include "dns.h"
#include "asn.h"
#include "display.h"
#include "graphcairo.h"

#define GC_ARGS_SEP	','
#define GC_ARGS_MAX	4
#ifdef IPINFO
#define HOSTSTAT_LEN	(3 * STARTSTAT + SAVED_PINGS)	// hostinfo + statistics
#else
#define HOSTSTAT_LEN	(STARTSTAT + SAVED_PINGS)	// hostname + statistics
#endif

#define	NUMHOSTS	10	// net.c:201 static numhosts = 10

extern int af;			// mtr.c
extern int mtrtype;
extern int maxTTL;
extern float WaitTime;

static int timeout;
static struct timeval lasttime;

static int flags;
#define F_PAUSED	0x01
#define F_LEGEND	0x02
#define F_MULTIPATH	0x04

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

void gc_set_header(void) {
	int len = 0;
	len += sprintf(legend_hd[LEGEND_HEADER_STATIC], "%s", "<b>");
	len += mtr_curses_data_fields(legend_hd[LEGEND_HEADER_STATIC] + len);
	len += sprintf(legend_hd[LEGEND_HEADER_STATIC] + len, "%s", "</b>");
}

int gc_open(void) {
	flags |= F_LEGEND;
	if (!args[2])
		flags &= ~F_LEGEND;

	flags |= F_MULTIPATH;
	if (!args[3])
		flags &= ~F_MULTIPATH;

	if ((data = malloc(maxTTL * sizeof(int))))
		memset(data, 0, maxTTL * sizeof(int));
	else {
		fprintf(stderr, "gc_open: malloc() failed\n");
		return 0;
	}

	timeout = POS_ROUND(WaitTime * USECONDS);
	gettimeofday(&lasttime, NULL);

	cr_params_t params;
	params.graph_type = (args[0] > 0) ? args[0] : 0;
	params.period = (args[1] > 0) ? args[1] : 0;
	params.enable_legend = (flags & F_LEGEND) ? 1 : 0;
	params.enable_multipath = (flags & F_MULTIPATH) ? 1 : 0;
	params.cols_max = SAVED_PINGS;
	params.path_max = MAXPATH;
	params.label_max = MAXLABELS;

	if (!cr_open(&params))
		return 0;

	if (flags & F_LEGEND) {
		gc_set_header();
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
		char *n, *p = strdup(arg);
		for (; (n = strchr(p, GC_ARGS_SEP)) && (i < GC_ARGS_MAX); i++, p = n) {
			*n++ = 0;
			args[i] = (*p) ? atoi(p) : -1;
		}
		if (p)
			args[i++] = (*p) ? atoi(p) : -1;
	}

	int j;
	for (j = i; j < GC_ARGS_MAX; j++)
		args[j] = -1;
}

void fill_hostinfo(int at, ip_t *addr) {
	int l, len = 0;
	char *p = buf;
	int sz;
#ifdef IPINFO
	if (enable_ipinfo) {
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
	char *name = dns_lookup(addr);
	if (name) {
		if (show_ips)
			l = snprintf(p, sz, "%s (%s)", name, strlongip(addr));
		else
			l = snprintf(p, sz, "%s", name);
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

void gc_keyaction(int c) {
	if (!c)
		return;

	if (c == ACTION_RESIZE) {
		if (flags & F_LEGEND) {
			curses_cols = cr_recalc(hostinfo_max);
			if (display_mode)
				sprintf(legend_hd[LEGEND_HEADER], "Last %d pings", curses_cols);
		}
		return;
	}

	if (flags & F_LEGEND) {
		switch (c) {
			case '+': {	// ScrollDown
				int hops = net_max() - net_min();
				display_offset += 5;
				if (display_offset >= hops)
					display_offset = hops - 1;
				hostinfo_max = 0;
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
			} break;
		}
		switch (tolower(c)) {
			case 'd':	// Display
				display_mode = (display_mode + 1) % 3;
				if (display_mode == 1) {
					curses_cols = cr_recalc(hostinfo_max);
					sprintf(legend_hd[LEGEND_HEADER], "Last %d pings", curses_cols);
				}
				break;
			case 'e':	// MPLS
				enablempls = !enablempls;
				break;
			case 'j':
				if (index(fld_active, 'N'))
					strcpy(fld_active, "DR AGJMXI");
				else
					strcpy(fld_active, "LS NABWV");
				gc_set_header();
				break;
			case 'n':	// DNS
				use_dns = !use_dns;
				hostinfo_max = 0;
				break;
#ifdef IPINFO
			case 'y':	// IP Info
				ii_action(0);
				hostinfo_max = 0;
				break;
			case 'z':	// ASN
				ii_action(1);
				hostinfo_max = 0;
				break;
#endif
		}
	}

	switch (c) {
		case 'q':	// Quit
			gc_close();
			exit(0);
			break;
		case ' ':	// Resume
			flags &= ~F_PAUSED;
			cr_net_reset(1);
			break;
	}
	switch (tolower(c)) {
		case 'p':	// Pause
			flags |= F_PAUSED;
			break;
		case 'r':	// Reset
			net_reset();
			cr_net_reset(0);
			num_pings = 0;
			break;
		case 't':	// TCP and ICMP ECHO
			switch (mtrtype) {
				case IPPROTO_ICMP:
				case IPPROTO_UDP:
					mtrtype = IPPROTO_TCP;
					break;
				case IPPROTO_TCP:
					mtrtype = IPPROTO_ICMP;
					break;
			}
			break;
		case 'u':	// UDP and ICMP ECHO
			switch (mtrtype) {
				case IPPROTO_ICMP:
				case IPPROTO_TCP:
					mtrtype = IPPROTO_UDP;
					break;
				case IPPROTO_UDP:
					mtrtype = IPPROTO_ICMP;
					break;
			}
			break;
	}
}

void gc_print_mpls(int i, int d, struct mplslen *mpls) {
	if (mpls) {
		int j;
		for (j = 0; (j < mpls->labels) && (j < MAXLABELS); j++) {
			sprintf(buf, "[MPLS: Lbl %lu Exp %u S %u TTL %u]",
				mpls->label[j], mpls->exp[j], mpls->s[j], mpls->ttl[j]);
			cr_print_host(i, d, buf, NULL);
		}
	}
}

void gc_redraw(void) {
	gc_keyaction(cr_dispatch_event());
	if (flags & F_PAUSED)
		return;

	int i, at;
	int min = net_min();
	int max = net_max();
	int hops = max - min /* + 1 */;
	if (!hops)
		hops++;

	cr_set_hops(hops, min);

	struct timeval now;
	gettimeofday(&now, NULL);
	int dt = (now.tv_sec - lasttime.tv_sec) * USECONDS + (now.tv_usec - lasttime.tv_usec);
	lasttime = now;

	if (dt < timeout) {
		int pings = net_xmit(min);
		for (at = min + 1; at < max; at++)
			if (net_xmit(at) != pings)
					return;
		if (pings > num_pings)
			num_pings = pings;
		else
			return;
	}

	int enable_legend = flags & F_LEGEND;
	int enable_multipath = flags & F_MULTIPATH;
	if (enable_legend) {
		static int hi_max;
		if (!hostinfo_max)
			   hi_max = 0;
		if (hostinfo_max > hi_max) {
			hi_max = hostinfo_max;
			curses_cols = cr_recalc(hostinfo_max);
			if (display_mode)
				sprintf(legend_hd[LEGEND_HEADER], "Last %d pings", curses_cols);
		}
		cr_init_legend();
		cr_print_legend_header(display_mode ? legend_hd[LEGEND_HEADER] : legend_hd[LEGEND_HEADER_STATIC]);
	}

	for (i = 0, at = min; i < hops; i++, at++) {
		ip_t *addr = net_addr(at);

		if (addrcmp((void *)addr, (void *)&unspec_addr, af) != 0) {
			int *saved = net_saved_pings(at);
/*
			int saved_int = saved[SAVED_PINGS - 1];
			if (saved_int == -2)	// unsent
				data[i] = net_up(at) ? net_last(at) : 0;
			else
				data[i] = (saved_int > 0) ? saved_int : 0;
*/
			int saved_int = saved[SAVED_PINGS - 2];	// waittime ago
			data[i] = (saved_int > 0) ? saved_int : 0;

			if (enable_legend) {
				// line+hop
				cr_print_hop(i);

				// hostinfo
				fill_hostinfo(at, addr);

				char *stat = buf + strlen(buf) + 1;
				// statistics
				if (display_mode) {
					mtr_gen_scale();
					char *pos = stat;
					int j;
					for (j = SAVED_PINGS - curses_cols; j < SAVED_PINGS; j++)
						*pos++ = mtr_curses_saved_char(saved[j]);
					*pos = 0;
				} else
					mtr_fill_data(at, stat);
				cr_print_host(i, data[i], buf, stat);

				// mpls
				if (enablempls)
					gc_print_mpls(i, data[i], net_mpls(at));

				// multipath
				if (enable_multipath) {
					int j;
					for (j = 0; j < MAXPATH; j++) {
						ip_t *addrs = net_addrs(at, j);
						if (addrcmp((void *)addrs, (void *)addr, af) == 0)
							continue;
						if (addrcmp((void *)addrs, (void *)&unspec_addr, af) == 0)
							break;
						fill_hostinfo(at, addrs);
						cr_print_host(i, data[i], buf, NULL);
						if (enablempls)	// multipath+mpls
							gc_print_mpls(i, data[i], net_mplss(at, j));
					}
				}
			}
		} else	// empty hop
			if (enable_legend) {
				cr_print_hop(i);
				cr_print_host(i, 0, NULL, NULL);
			}
	}

	if (enable_legend)
		if (display_mode) {
			int len = sprintf(legend_hd[LEGEND_FOOTER], "<b>Scale:</b>");
			mtr_curses_scale_desc(legend_hd[LEGEND_FOOTER] + len);
			cr_print_legend_footer(legend_hd[LEGEND_FOOTER]);
		}

	cr_redraw(data);

	if (hops)
		timeout = POS_ROUND(((WaitTime * hops) / NUMHOSTS) * USECONDS);
}

