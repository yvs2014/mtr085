
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "config.h"
#include "mtr.h"
#include "net.h"
#include "graphcairo-curses.h"

#define GC_NUM_FACTORS	8		// curses.c:429 define NUM_FACTORS
static double factors[GC_NUM_FACTORS];	// curses.c:430 static factors
static int scale[GC_NUM_FACTORS];	// curses.c:431 static scale
static int low_ms, high_ms;		// curses.c:432 static low_ms, high_ms

extern int display_offset;
extern int display_mode;

void gc_curses_gen_scale(void) {	// curses.c:434 mtr_gen_scale()
	int *saved, i, max, at;
	int range;
	low_ms = 1000000;
	high_ms = -1;

	max = net_max();
	for (at = display_offset; at < max; at++) {
		saved = net_saved_pings(at);
		for (i = 0; i < SAVED_PINGS; i++) {
			if (saved[i] < 0)
				continue;
			if (saved[i] < low_ms)
				low_ms = saved[i];
			if (saved[i] > high_ms)
				high_ms = saved[i];
		}
	}
	range = high_ms - low_ms;
	for (i = 0; i < GC_NUM_FACTORS; i++)
		scale[i] = low_ms + ((double)range * factors[i]);
}

static char block_map[GC_NUM_FACTORS];	// curses.c:465 static block_map

void gc_curses_init(void) {	// curses.c:467 mtr_curses_init()
	int i;
	/* Initialize factors to a log scale. */
	for (i = 0; i < GC_NUM_FACTORS; i++) {
		factors[i] = ((double)1 / GC_NUM_FACTORS) * (i + 1);
		factors[i] *= factors[i]; /* Squared. */
	}

	int block_split;
	/* Initialize block_map. */
	block_split = (GC_NUM_FACTORS - 2) / 2;
	if (block_split > 9)
		block_split = 9;

	block_map[0] = '.';
	for (i = 1; i <= block_split; i++)
		block_map[i] = '0' + i;
	for (i = block_split + 1; i < GC_NUM_FACTORS - 1; i++)
		block_map[i] = 'a' + i - block_split - 1;
	block_map[GC_NUM_FACTORS - 1] = '>';
}

char gc_curses_print_scaled(int ms) {	// curses.c:493 mtr_print_scaled()
	int i;
	for (i = 0; i < GC_NUM_FACTORS; i++)
		if (ms <= scale[i])
			return block_map[i];
	return '>';
}

char gc_curses_saved_char(int saved_int) {
	if (saved_int == -2)
		return ' ';
	if (saved_int == -1)
		return '?';
	if (display_mode != 1)
		return gc_curses_print_scaled(saved_int);
	if (saved_int > scale[6])
		return block_map[GC_NUM_FACTORS-1];
	return '.';
}

void gc_curses_set_legend(int max_cols, int sz, char *msg_top, char *msg_bottom) {
	snprintf(msg_top, sz, "Last %d pings", max_cols);
	snprintf(msg_bottom, sz, "<b>Scale:</b>");
	int i, len = strnlen(msg_bottom, sz);
	for (i = 0; i < GC_NUM_FACTORS - 1; i++) {
		int l = snprintf(msg_bottom + len, sz - len, "  %c:%d ms",
				block_map[i], scale[i] / 1000);
		len += l;
	}
}
 
