
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/time.h>

#include "config.h"
#include "mtr.h"
#include "net.h"
#include "dns.h"
#include "asn.h"
#include "display.h"
#include "graphcairo.h"
#include "graphcairo-curses.h"	// for display_mode!=0 only

#define GC_ARGS_SEP	','
#define GC_ARGS_MAX	4
#define PADDING	30	// curses.c:644 local padding = 30
#define HOSTSTAT_LEN	(PADDING + PADDING + SAVED_PINGS)	// hostinfo + statistics

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
static char buf[PADDING + PADDING + SAVED_PINGS];

enum {
	LEGEND_HEADER_STATIC,
	LEGEND_HEADER,
	LEGEND_FOOTER
};
#define LEGEND_HD_NO    3
static char legend_hd[LEGEND_HD_NO][SAVED_PINGS];

static int curses_cols;

void get_legend_hd(void) {
	int len = 0;
	snprintf(legend_hd[LEGEND_HEADER_STATIC], HOSTSTAT_LEN, "%s", "<b>"); len += 3;
	char fmt[16];
	int i;
	for (i = 0; i < MAXFLD; i++) {	// curses.c:625-632
		int j = fld_index[fld_active[i]];
		if (j < 0)
		   	continue;
		snprintf(fmt, sizeof(fmt), "%%%ds", data_fields[j].length);
		snprintf(legend_hd[LEGEND_HEADER_STATIC] + len, HOSTSTAT_LEN - len, fmt, data_fields[j].title);
		len += data_fields[j].length;
	}
	snprintf(legend_hd[LEGEND_HEADER_STATIC] + len, HOSTSTAT_LEN - len, "%s", "</b>"); len += 4;
	cr_restat(legend_hd[display_mode ? LEGEND_HEADER : LEGEND_HEADER_STATIC]);
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
		get_legend_hd();
		gc_curses_init();
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

void fill_hostinfo(ip_t *addr) {
	int len = 0;
	int sz = sizeof(buf);
	char *p = buf;
#ifdef IPINFO
	if (enable_ipinfo) {
		char *fmt_ii = fmt_ipinfo(addr);
		snprintf(p, sz, "%s", fmt_ii);
		len = strnlen(fmt_ii, sz);
		p += len;
		sz -= len;
	}
#endif
	char *name = dns_lookup(addr);
	if (name) {
		if (show_ips)
			snprintf(p, sz, "%s (%s)", name, strlongip(addr));
		else
			snprintf(p, sz, "%s", name);
	} else
		snprintf(p, sz, "%s", strlongip(addr));
}

void gc_keyaction(int c) {
	if (!c)
		return;

	if (c == ACTION_RESIZE) {
		if (display_mode) {
			curses_cols = cr_get_cols(0);
			gc_curses_set_legend(curses_cols, HOSTSTAT_LEN,
				legend_hd[LEGEND_HEADER], legend_hd[LEGEND_FOOTER]);
		}
		cr_restat(legend_hd[display_mode ? LEGEND_HEADER : LEGEND_HEADER_STATIC]);
		return;
	}

	if (flags & F_LEGEND) {
		switch (c) {
			case '+':	// ScrollDown
				if (display_offset > (net_max() - net_min()))
					break;
				display_offset += 5;
				break;
			case '-':	// ScrollUp
				display_offset -= 5;
				if (display_offset < 0)
					display_offset = 0;
				break;
		}
		switch (tolower(c)) {
			case 'd':	// Display
				display_mode = (display_mode + 1) % 3;
				if (display_mode == 1) {
					int max = net_max();
					int hostinfo_len = 0;
					int i;
					for (i = net_min(); i < max; i++) {
						ip_t *addr = net_addr(i);
						if (addrcmp((void *)addr, (void *)&unspec_addr, af) != 0) {
							fill_hostinfo(addr);
							int l = strnlen(buf, sizeof(buf));
							if (l > hostinfo_len)
								hostinfo_len = l;
						}
					}
					curses_cols = cr_get_cols(hostinfo_len);
				}
				if (display_mode)
					gc_curses_set_legend(curses_cols, HOSTSTAT_LEN,
						legend_hd[LEGEND_HEADER], legend_hd[LEGEND_FOOTER]);
				cr_restat(legend_hd[display_mode ? LEGEND_HEADER : LEGEND_HEADER_STATIC]);
				break;
			case 'e': 	// MPLS
				enablempls = !enablempls;
				break;
			case 'j':
				if (index(fld_active, 'N'))
					strcpy(fld_active, "DR AGJMXI");
				else
					strcpy(fld_active, "LS NABWV");
				get_legend_hd();
				break;
			case 'n':	// DNS
				use_dns = !use_dns;
				cr_restat(legend_hd[display_mode ? LEGEND_HEADER : LEGEND_HEADER_STATIC]);
				break;
#ifdef IPINFO
			case 'y':	// IP Info
				ii_action(0);
				cr_restat(legend_hd[display_mode ? LEGEND_HEADER : LEGEND_HEADER_STATIC]);
				break;
			case 'z':	// ASN
				ii_action(1);
				cr_restat(legend_hd[display_mode ? LEGEND_HEADER : LEGEND_HEADER_STATIC]);
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
			snprintf(buf, sizeof(buf), "[MPLS: Lbl %lu Exp %u S %u TTL %u]",
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

	cr_set_hops(hops, min);

	int enable_legend = flags & F_LEGEND;
	int enable_multipath = flags & F_MULTIPATH;
	if (enable_legend)
		cr_init_print();

	for (i = 0, at = min; i < hops; i++, at++) {
		ip_t *addr = net_addr(at);

		if (addrcmp((void *)addr, (void *)&unspec_addr, af) != 0) {
			int *saved = net_saved_pings(at);
			int saved_int = saved[SAVED_PINGS - 1];
			if (saved_int == -2)	// unsent
				data[i] = net_up(at) ? net_last(at) : 0;
			else
				data[i] = (saved_int > 0) ? saved_int : 0;

			if (enable_legend) {
				// line+hop
				cr_print_hop(i);

				// hostinfo
				fill_hostinfo(addr);

				char *stat = buf + strnlen(buf, sizeof(buf)) + 1;
				// statistics
				if (display_mode) {
					gc_curses_gen_scale();
					char *pos = stat;
					int j;
					for (j = SAVED_PINGS - curses_cols; j < SAVED_PINGS; j++)
						*pos++ = gc_curses_saved_char(saved[j]);
					*pos = 0;
				} else {
					int len = 0, k;
					for (k = 0; k < MAXFLD; k++) {	// curses.c:364-380
						int j = fld_index[fld_active[k]];
						if (j < 0)
							continue;
						const char *format = data_fields[j].format;
						int net_xxx = data_fields[j].net_xxx(at);
						if (index(format, 'f'))
							snprintf(stat + len, SAVED_PINGS - len, format, net_xxx / 1000.0);
						else
							snprintf(stat + len, SAVED_PINGS - len, format, net_xxx);
						len += data_fields[j].length;
						if (len >= SAVED_PINGS)
							break;
					}
				}
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
						fill_hostinfo(addrs);
						cr_print_host(i, data[i], buf, NULL);
						if (enablempls)	// multipath+mpls
							gc_print_mpls(i, data[i], net_mplss(at, j));
					}
				}
			}
		}
	}

	if (enable_legend && display_mode)
		cr_print_legend_footer(legend_hd[LEGEND_FOOTER]);

	cr_redraw(data);

	if (hops)
		timeout = POS_ROUND(((WaitTime * hops) / NUMHOSTS) * USECONDS);
}

