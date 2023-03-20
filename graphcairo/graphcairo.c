
#include <math.h>
#include <sys/time.h>
#include <cairo.h>
#include <pango/pangocairo.h>

#include "config.h"
#include "mtr.h"
#include "net.h"

#ifdef UNICODE
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#endif

#include "graphcairo.h"
#include "graphcairo-backend.h"

/*
  Cairo backends:
  - X11 XCB
  - X11 Xlib
*/
#ifndef GRAPHCAIRO_XCB
#ifndef GRAPHCAIRO_XLIB
#error "No cairo backend defined"
#endif
#endif

enum {
	CR_BASE,
	CR_WORK,
	CR_GRID,
	CR_LGND,
	CR_LAYR,
	CR_TEMP
};
#define CAIRO_SURFACES	6

typedef struct {
	cairo_t *cairo;
	cairo_surface_t *surface;
	cairo_rectangle_int_t *rectangle;
	PangoLayout *pango;
	PangoFontDescription *font_desc;
} cairos_t;
static cairos_t cairos[CAIRO_SURFACES];

enum {
	GRAPHTYPE_NONE,
	GRAPHTYPE_DOT,
	GRAPHTYPE_LINE,
	GRAPHTYPE_CURVE
};

enum {
	TM_MMSS,
	TM_HHMM
};

#define DATAMAX		5000	// in usec	(y-axis)
#define VIEWPORT_TIMEPERIOD	60	// in sec	(x-axis)

#define MARGIN_LEFT		2.0	// in dx
#define MARGIN_RIGHT		1.3	// in dx
#define MARGIN_TOP		1.0	// in dy
#define MARGIN_BOTTOM		1.3	// in dy
#define GRID_RGB		0.7
#define FONT_SIZE		0.3	// in cells
#define TICKLABEL_LEN		5
#define GRIDLINES		10
#define GRAPHFUNCS_MAX		3
#define DOT_SIZE		3
#define CYCLE_FACTOR		1.0

typedef void (*graph_func_t)(cairo_t *cr);
static graph_func_t graph_func;

typedef void (*set_source_rgb_func_t)(cairo_t *cr, int i);
static set_source_rgb_func_t set_source_rgb_func;

static cr_params_t *params;

#define SPLINE_POINTS	4
static int x_point[SPLINE_POINTS];
static int *y_point[SPLINE_POINTS];
typedef struct {
	long long data;
	int count;
} unclosed_data_t;
static unclosed_data_t *unclosed_data;

static cairo_rectangle_int_t base_window = { 0, 0, 780, 520 };
static cairo_rectangle_int_t vp;	// viewport
static cairo_rectangle_int_t vp_prev;
static cairo_rectangle_int_t vp_layer;
static cairo_rectangle_int_t grid;
static cairo_rectangle_int_t legend;
static cairo_rectangle_int_t cell; // x,y: horizontal/vertical gridlines

static int font_size;
static int tick_size;
static int datamax, datamax_prev;
static int hops, first_hop;
static int x_point_in_usec;
static int action;
static int tm_fmt;
static struct timeval lasttime;

typedef struct {
	int hop_x;
	int host_x;
	int stat_x;
	int text_y;
	int line_y;
	int dy;
	int label_w;
	int stat_max;
	int footer_max;
} legend_coords_t;
static legend_coords_t coords;

//static double cr_greycolors[] = { 0, 0.5, 0.75, 0.25, 0.125, 0.375, 0.625, 0.875, ...
static double cr_colors[][3] = { // 128 g.e. default ttl in various systems
	{1.0, 0, 0}, {0, 1.0, 0}, {0, 0, 1.0}, {1.0, 1.0, 0}, {1.0, 0, 1.0}, {0, 1.0, 1.0},
	{0.5, 0, 0}, {0, 0.5, 0}, {0, 0, 0.5}, {0.5, 0.5, 0}, {0.5, 0, 0.5}, {0, 0.5, 0.5},
	{0.75, 0, 0}, {0, 0.75, 0}, {0, 0, 0.75}, {0.75, 0.75, 0}, {0.75, 0, 0.75}, {0, 0.75, 0.75},
	{0.25, 0, 0}, {0, 0.25, 0}, {0, 0, 0.25}, {0.25, 0.25, 0}, {0.25, 0, 0.25}, {0, 0.25, 0.25},
	{0.875, 0, 0}, {0, 0.875, 0}, {0, 0, 0.875}, {0.875, 0.875, 0}, {0.875, 0, 0.875}, {0, 0.875, 0.875},
	{0.625, 0, 0}, {0, 0.625, 0}, {0, 0, 0.625}, {0.625, 0.625, 0}, {0.625, 0, 0.625}, {0, 0.625, 0.625},
	{0.375, 0, 0}, {0, 0.375, 0}, {0, 0, 0.375}, {0.375, 0.375, 0}, {0.375, 0, 0.375}, {0, 0.375, 0.375},
	{0.125, 0, 0}, {0, 0.125, 0}, {0, 0, 0.125}, {0.125, 0.125, 0}, {0.125, 0, 0.125}, {0, 0.125, 0.125},
	{0.9375, 0, 0}, {0, 0.9375, 0}, {0, 0, 0.9375}, {0.9375, 0.9375, 0}, {0.9375, 0, 0.9375}, {0, 0.9375, 0.9375},
	{0.8125, 0, 0}, {0, 0.8125, 0}, {0, 0, 0.8125}, {0.8125, 0.8125, 0}, {0.8125, 0, 0.8125}, {0, 0.8125, 0.8125},
	{0.6875, 0, 0}, {0, 0.6875, 0}, {0, 0, 0.6875}, {0.6875, 0.6875, 0}, {0.6875, 0, 0.6875}, {0, 0.6875, 0.6875},
	{0.5625, 0, 0}, {0, 0.5625, 0}, {0, 0, 0.5625}, {0.5625, 0.5625, 0}, {0.5625, 0, 0.5625}, {0, 0.5625, 0.5625},
	{0.4375, 0, 0}, {0, 0.4375, 0}, {0, 0, 0.4375}, {0.4375, 0.4375, 0}, {0.4375, 0, 0.4375}, {0, 0.4375, 0.4375},
	{0.3125, 0, 0}, {0, 0.3125, 0}, {0, 0, 0.3125}, {0.3125, 0.3125, 0}, {0.3125, 0, 0.3125}, {0, 0.3125, 0.3125},
	{0.1875, 0, 0}, {0, 0.1875, 0}, {0, 0, 0.1875}, {0.1875, 0.1875, 0}, {0.1875, 0, 0.1875}, {0, 0.1875, 0.1875},
	{0.0625, 0, 0}, {0, 0.0625, 0}, {0, 0, 0.0625}, {0.0625, 0.0625, 0}, {0.0625, 0, 0.0625}, {0, 0.0625, 0.0625},
	{0.96875, 0, 0}, {0, 0.96875, 0}, {0, 0, 0.96875}, {0.96875, 0.96875, 0}, {0.96875, 0, 0.96875}, {0, 0.96875, 0.96875},
	{0.90625, 0, 0}, {0, 0.90625, 0}, {0, 0, 0.90625}, {0.90625, 0.90625, 0}, {0.90625, 0, 0.90625}, {0, 0.90625, 0.90625},
	{0.84375, 0, 0}, {0, 0.84375, 0}, {0, 0, 0.84375}, {0.84375, 0.84375, 0}, {0.84375, 0, 0.84375}, {0, 0.84375, 0.84375},
	{0.78125, 0, 0}, {0, 0.78125, 0}, {0, 0, 0.78125}, {0.78125, 0.78125, 0}, {0.78125, 0, 0.78125}, {0, 0.78125, 0.78125},
	{0.71875, 0, 0}, {0, 0.71875, 0}, {0, 0, 0.71875}, {0.71875, 0.71875, 0}, {0.71875, 0, 0.71875}, {0, 0.71875, 0.71875},
	{0.65625, 0, 0}, {0, 0.65625, 0}, /*{0, 0, 0.65625}, {0.65625, 0.65625, 0}, {0.65625, 0, 0.65625}, {0, 0.65625, 0.65625}, */
};
static int cr_colors_max = sizeof(cr_colors) / sizeof(cr_colors[0]);


static int cr_check_status(cairo_t *cr, char *s) {
	int status = cairo_status(cr);
	if (status) {
		fprintf(stderr, "cr_check_status(): %s failed: %s\n", s, cairo_status_to_string(status));
		return 0;
	}
	return 1;
}

static void swap_cairos(int ndx1, int ndx2) {
	cairos_t cairos_temp = cairos[ndx1];
	cairos[ndx1] = cairos[ndx2];
	cairos[ndx2] = cairos_temp;
}

static int cr_create_similar(int ndx, int similar, cairo_rectangle_int_t *r) {
	cairos[ndx].rectangle = r;
	if (cairos[ndx].surface)
		cairo_surface_destroy(cairos[ndx].surface);
	if (cairos[ndx].cairo)
		cairo_destroy(cairos[ndx].cairo);

	if (similar >= 0)
		cairos[ndx].surface = cairo_surface_create_similar(cairos[similar].surface,
			CAIRO_CONTENT_COLOR_ALPHA, r->width, r->height);
	else
		cairos[ndx].surface = backend_create_surface(r->width, r->height);

	if (!cairos[ndx].surface) {
		fprintf(stderr, "cr_create_similar(): surface creation failed\n");
		return 0;
	}
	cairos[ndx].cairo = cairo_create(cairos[ndx].surface);
	return cr_check_status(cairos[ndx].cairo, "cr_create_similar()");
}

static int cr_recreate_surfaces(int save) {
	if (save)
		swap_cairos(CR_WORK, CR_TEMP);
	if (cr_create_similar(CR_BASE, -1, &base_window)) {
		cairo_set_source_rgb(cairos[CR_BASE].cairo, 1, 1, 1);
		cairo_paint(cairos[CR_BASE].cairo);
	} else
		return 0;
	if (!cr_create_similar(CR_WORK, CR_BASE, &vp))
		return 0;
	if (!cr_create_similar(CR_GRID, CR_BASE, &grid))
		return 0;
	if (params->enable_legend)
		if (!cr_create_similar(CR_LGND, CR_BASE, &legend))
			return 0;
	if (params->graph_type == GRAPHTYPE_CURVE)
		if (!cr_create_similar(CR_LAYR, CR_BASE, &vp_layer))
			return 0;
	return save ? 1 : cr_create_similar(CR_TEMP, CR_BASE, &vp);
}

static int cr_fill_base(int src) {
	cairo_t *dst = cairos[CR_BASE].cairo;
	cairo_set_source_surface(dst, cairos[src].surface, cairos[src].rectangle->x, cairos[src].rectangle->y);
	cairo_rectangle(dst, cairos[src].rectangle->x, cairos[src].rectangle->y,
		cairos[src].rectangle->width, cairos[src].rectangle->height);
	cairo_fill(dst);
	return cr_check_status(dst, "cr_fill_base()");
}

static void cr_paint(void) {
	cr_fill_base(CR_WORK);
	if (params->graph_type == GRAPHTYPE_CURVE)
		cr_fill_base(CR_LAYR);
	cr_fill_base(CR_GRID);
	if (params->enable_legend)
		cr_fill_base(CR_LGND);
	backend_flush();
}

static int cr_pango_open(int ndx) {
	static char *font_family = "monospace";

	if (!(cairos[ndx].font_desc = pango_font_description_new()))
		return 0;
	pango_font_description_set_family(cairos[ndx].font_desc, font_family);
	pango_font_description_set_absolute_size(cairos[ndx].font_desc, font_size * PANGO_SCALE);
	if (!(cairos[ndx].pango = pango_cairo_create_layout(cairos[ndx].cairo)))
		return 0;
	pango_layout_set_font_description(cairos[ndx].pango, cairos[ndx].font_desc);

	return 1;
}

static void set_viewport_params() {
	vp_prev = vp;

	double margin_right = MARGIN_RIGHT;
	double margin_bottom = MARGIN_BOTTOM;
	if (params->enable_legend)
		margin_bottom += 8;

	double d;
	d = (base_window.width * (GRIDLINES + MARGIN_TOP + margin_bottom)) /
		(base_window.height * (GRIDLINES + MARGIN_LEFT + margin_right)) + 0.2;
	if (d > 1) {
		cell.x = GRIDLINES;
		cell.y = GRIDLINES * POS_ROUND(d);
	} else {
		cell.y = GRIDLINES;
		cell.x = GRIDLINES * POS_ROUND(1 / d);
	}

	d = base_window.width / (MARGIN_LEFT + margin_right + cell.y);
	cell.width = POS_ROUND(d);
	d = base_window.height / (MARGIN_TOP + margin_bottom + cell.x);
	cell.height = POS_ROUND(d);

	vp.x = POS_ROUND(MARGIN_LEFT * cell.width);
	vp.y = POS_ROUND(MARGIN_TOP  * cell.height);
	vp.width = cell.y * cell.width;
	vp.height = cell.x * cell.height;
	vp_layer = vp;

	x_point_in_usec = POS_ROUND((USECONDS * (double)params->period) / vp.width);
	tick_size = cell.width / 8;
	font_size = POS_ROUND(FONT_SIZE * cell.height);

	grid.x = 0;
	grid.y = vp.y - font_size;
	grid.width = vp.x + vp.width + tick_size;
	grid.height = font_size + vp.height + tick_size;

	if (!x_point[0])
		x_point[0] = vp.width;

	if (params->enable_legend) {
		legend.x = vp.x;
		legend.y = vp.y + vp.height + 3 * font_size;
		legend.width = vp.width;
		legend.height = vp.height;
	}

#ifdef GCDEBUG
	printf("window=(%d, %d), ", base_window.width, base_window.height);
	printf("viewport=(%d, %d, %d, %d), ", vp.x, vp.y, vp.width, vp.height);
	if (params->enable_legend)
		printf("legend=(%d, %d, %d, %d), ", legend.x, legend.y, legend.width, legend.height);
	int xp = x_point_in_usec;
	char scale = 'u';
	if (xp > 10*1000000) {
		xp = POS_ROUND((double)xp / 1000000);
		scale = 0;
	} else
		if (xp > 10*1000) {
			xp = POS_ROUND((double)xp / 1000);
			scale = 'm';
		}
	printf("x-point=%d%csec\n", xp, scale);
#endif
}

static void draw_grid(void) {
	cairo_t *cr = cairos[CR_GRID].cairo;
	PangoLayout *pl = cairos[CR_GRID].pango;

	// x-axis, y-axis
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, vp.x, font_size - tick_size);
	cairo_rel_line_to(cr, 0, vp.height + tick_size);
	cairo_rel_line_to(cr, vp.width + tick_size, 0);

	// x-ticks, y-ticks
	for (int i = 0, a = font_size; i < cell.x; i++, a += cell.height) {
		cairo_move_to(cr, vp.x, a);
		cairo_rel_line_to(cr, -tick_size, 0);
	}
	for (int i = 0, a = vp.x + cell.width; i < cell.y; i++, a += cell.width) {
		cairo_move_to(cr, a, grid.height);
		cairo_rel_line_to(cr, 0, -tick_size);
	}
	cairo_stroke(cr);

	// gridlines
	static const double dash[] = {1.0};
	cairo_set_dash(cr, dash, 1, 0);
	cairo_set_source_rgb(cr, GRID_RGB, GRID_RGB, GRID_RGB);
	for (int i = 0, a = font_size; i < cell.x; i++, a += cell.height) {
		cairo_move_to(cr, vp.x, a);
		cairo_rel_line_to(cr, vp.width + tick_size, 0);
	}
	for (int i = 0, a = vp.x + cell.width; i < cell.y; i++, a += cell.width) {
		cairo_move_to(cr, a, font_size - tick_size);
		cairo_rel_line_to(cr, 0, vp.height + tick_size);
	}
	cairo_stroke(cr);

	// y-axis tick marks
	int pl_width = vp.x - 3 * tick_size;
	pango_layout_set_width(pl, pl_width * PANGO_SCALE);
	pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, 0, 0, pl_width, grid.height);
	cairo_fill(cr);
	char fmt[16];
	char buf[16];
	sprintf(fmt, "%%%d.1f", TICKLABEL_LEN);
	cairo_set_source_rgb(cr, 0, 0, 0);
	double coef1 = (double)datamax / (cell.x * 1000);	// 1000: usec -> msec
	for (int i = 0, a = vp.height; i <= cell.x; i++, a -= cell.height) {
		cairo_move_to(cr, 0, a);
		sprintf(buf, fmt, coef1 * i);
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
	}

	// plus axis labels
	cr = cairos[CR_BASE].cairo;
	pl = cairos[CR_BASE].pango;

	cairo_set_source_rgb(cr, 1, 1, 1);
	int xl_x = vp.x + vp.width + tick_size * 2;
	int xl_y = vp.y + vp.height - font_size;
	cairo_rectangle(cr, xl_x, xl_y, coords.label_w, font_size);
	cairo_fill(cr);
	pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, xl_x, xl_y);
	pango_layout_set_text(pl, (tm_fmt == TM_HHMM) ? "HH:MM" : "Time", -1);
	pango_cairo_show_layout(cr, pl);

	cairo_move_to(cr, vp.x + tick_size, grid.y - font_size * 3 / 2);
	cairo_set_source_rgb(cr, 1, 1, 1);
	int yl_y = grid.y - font_size * 3 / 2;
	cairo_rectangle(cr, 0, yl_y, vp.x + coords.label_w, font_size);
	cairo_fill(cr);
	pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, vp.x + tick_size, yl_y);
	pango_layout_set_text(pl, "msec", -1);
	pango_cairo_show_layout(cr, pl);
	pango_layout_set_width(pl, vp.x * PANGO_SCALE);
	pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);
	cairo_move_to(cr, 0, yl_y);
	pango_layout_set_text(pl, params->jitter_graph ? "Jitter," : "Latency,", -1);
	pango_cairo_show_layout(cr, pl);
}

static void scale_viewport(void) {
	cairo_t *cr = cairos[CR_TEMP].cairo;
	cairo_save(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_paint(cr);

	double sy = (double)datamax_prev / datamax;
	cairo_matrix_t m;
	cairo_matrix_init(&m, 1, 0, 0, sy, 0, vp.height * (1 - sy));
	cairo_transform(cr, &m);
	cairo_set_source_surface(cr, cairos[CR_WORK].surface, 0, 0);
	cairo_paint(cr);
	cairo_restore(cr);
	swap_cairos(CR_WORK, CR_TEMP);
}

static int data_scale(int data) {
	return (data >= 0) ? POS_ROUND(vp.height * (1 - (double)data / datamax)) : 0;
}

static void set_source_rgb_mod(cairo_t *cr, int i) {
	int ndx = i % cr_colors_max;
	cairo_set_source_rgb(cr, cr_colors[ndx][0], cr_colors[ndx][1], cr_colors[ndx][2]);
}
static void set_source_rgb_dir(cairo_t *cr, int i) {
	cairo_set_source_rgb(cr, cr_colors[i][0], cr_colors[i][1], cr_colors[i][2]);	// maxTTL l.e. colors_max
}

static void draw_dot(cairo_t *cr, int i, int x0, int y0) {
	set_source_rgb_func(cr, i);
	cairo_move_to(cr, x_point[0], y0);
	cairo_close_path(cr);
	cairo_stroke(cr);
}

static void draw_line(cairo_t *cr, int i, int x0, int y0, int x1, int y1) {
	set_source_rgb_func(cr, i);
	cairo_move_to(cr, x0, y0);
	cairo_line_to(cr, x1, y1);
	cairo_stroke(cr);
}

static void graph_dot(cairo_t *cr) {
	cairo_save(cr);
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_width(cr, DOT_SIZE);
	int x0 = x_point[0];
	int i;
	for (i = display_offset; i < hops; i++) {
		int y0 = y_point[0][i];
		if (y0)
			draw_dot(cr, i, x0, y0);
	}
	cairo_restore(cr);
}

static void graph_line(cairo_t *cr) {
	int x0 = x_point[0];
	int x1 = x_point[1];
	int i;
	for (i = display_offset; i < hops; i++) {
		int y0 = y_point[0][i];
		int y1 = y_point[1][i];
		if (y0 && y1)
			draw_line(cr, i, x0, y0, x1, y1);
		else if (y1) {
			cairo_save(cr);
			cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
			cairo_set_line_width(cr, DOT_SIZE);
			draw_dot(cr, i, x1, y1);
			cairo_restore(cr);
		}
	}
	int *tmp = y_point[1];
	y_point[1] = y_point[0];
	y_point[0] = tmp;
}

static double distance(int x0, int y0, int x1, int y1) {
	int dx1 = x1 - x0; int dy1 = y1 - y0;
	return sqrt(dx1 * dx1 + dy1 * dy1);
}

static int centripetal(double d1, double q1, double d2, double q2, int p0, int p1, int p2) {
	double b = (d1*p0 - d2*p1 + (2*d1 + 3*q1*q2 + d2)*p2) / (3*q1*(q1 + q2));
	return POS_ROUND(b);
}

static void graph_curve(cairo_t *cr) {
	int x3 = x_point[0];
	int x2 = x_point[1];
	int x1 = x_point[2];
	int x0 = x_point[3];

	int i;
	for (i = display_offset; i < hops; i++) {
		int y3 = y_point[0][i];
		int y2 = y_point[1][i];
		int y1 = y_point[2][i];
		int y0 = y_point[3][i];

		if (y0 && y1 && y2 && y3) {
			int ax, ay, bx, by;
			double d1 = distance(x0, y0, x1, y1);
			double d2 = distance(x1, y1, x2, y2);
			double d3 = distance(x2, y2, x3, y3);
			if ((d1 != 0) && (d2 != 0) && (d3 != 0)) {
/*
  Centripetal Catmull-Rom spline:

     d1*p2 - d2*p0 + (2d1 + 3 * d1^1/2 * d2^1/2 + d2)*p1
b1 = ---------------------------------------------------
     3d1^1/2 * (d1^1/2 + d2^1/2)

     d3*p1 - d2*p3 + (2d3 + 3 * d3^1/2 * d2^1/2 + d2)*p2
b2 = ---------------------------------------------------
     3d3^1/2 * (d3^1/2 + d2^1/2)
*/
				double q1 = sqrt(d1);
				double q2 = sqrt(d2);
				double q3 = sqrt(d3);
				ax = centripetal(d1, q1, d2, q2, x2, x0, x1);
				ay = centripetal(d1, q1, d2, q2, y2, y0, y1);
				bx = centripetal(d3, q3, d2, q2, x1, x3, x2);
				by = centripetal(d3, q3, d2, q2, y1, y3, y2);
			} else {
/*
  Uniform Catmull-Rom spline (unparameterized implemenatation):
	b1 = p1 + (p2 - p0) / 6
	b2 = p2 - (p3 - p1) / 6
*/
				ax = x1 + (x2 - x0) / 6;
				ay = y1 + (y2 - y0) / 6;
				bx = x2 - (x3 - x1) / 6;
				by = y2 - (y3 - y1) / 6;
			}

			set_source_rgb_func(cr, i);
			cairo_move_to(cr, x1, y1);
			cairo_curve_to(cr, ax, ay, bx, by, x2, y2);
//			cairo_line_to(cr, x3, y3);
			cairo_stroke(cr);
		} else if (y1 && y2)
			draw_line(cr, i, x1, y1, x2, y2);
		else if (y2) {
			cairo_save(cr);
			cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
			cairo_set_line_width(cr, DOT_SIZE);
			draw_dot(cr, i, x2, y2);
			cairo_restore(cr);
		}

		if (y2 && y3) {
			cairo_t *cl = cairos[CR_LAYR].cairo;
			set_source_rgb_func(cl, i);
			cairo_move_to(cl, 0, y2);
			cairo_line_to(cl, x3 - x2, y3);
			cairo_stroke(cl);
		}
	}

	int *tmp = y_point[3];
	y_point[3] = y_point[2];
	y_point[2] = y_point[1];
	y_point[1] = y_point[0];
	y_point[0] = tmp;
}

#ifdef UNICODE
static void print_legend_desc(int x, int y, char *desc, int desc_max, bool is_wide) {
#else
static void print_legend_desc(int x, int y, char *desc, int desc_max) {
#endif
	if (desc) {
		cairo_t *cr = cairos[CR_LGND].cairo;
		PangoLayout *pl = cairos[CR_LGND].pango;

		char *s;
#ifdef UNICODE
		if (is_wide) {
			static char mbs[1024];
			wcstombs(mbs, (wchar_t*)desc, 1024);
			s = mbs;
		} else
#endif
			s = desc;

/*
		char *txt;
		PangoAttrList *attrs;
		pango_parse_markup(s, -1, 0, &attrs, &txt, NULL, NULL);
		if (!txt)
			return;
		if (strlen(txt) > desc_max)
			txt[desc_max] = 0;
*/
		if (strlen(s) > desc_max)
			s[desc_max] = 0;
		pango_layout_set_width(pl, (legend.width - x) * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);
		pango_layout_set_text(pl, s, -1);
//		pango_layout_set_text(pl, txt, -1);
//		pango_layout_set_attributes(pl, attrs);

		cairo_move_to(cr, x, y);
		cairo_set_source_rgb(cr, 0, 0, 0);
		pango_cairo_show_layout(cr, pl);
		pango_layout_set_attributes(pl, NULL);	// unref
//		pango_attr_list_unref(attrs);
//		free(txt);

		pango_layout_set_width(pl, -1);
		pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
	}
}

int cr_recalc(int hostinfo_max) {
	int w, h;
	PangoLayout *pl = cairos[CR_LGND].pango;
	pango_layout_set_text(pl, ".", -1);
	pango_layout_get_pixel_size(pl, &w, &h);
	coords.dy = (h * 3) / 2;
	coords.label_w = 5 * w;
	coords.hop_x = cell.width + w;
	coords.host_x = coords.hop_x + (w * 7) / 2;
	coords.stat_x = coords.host_x + (hostinfo_max + 1) * w;
	coords.stat_max = (legend.width - coords.stat_x) / w;

	if (coords.stat_max < 0)
		coords.stat_max = 0;
	if (coords.stat_max > params->cols_max)
		coords.stat_max = params->cols_max;
	coords.footer_max = legend.width / w;
	return coords.stat_max;
}

void cr_init_legend(void) {
	coords.text_y = coords.dy;
	coords.line_y = coords.text_y + font_size / 2 + 1;
	cairo_t *cr = cairos[CR_LGND].cairo;
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_paint(cr);
}

void cr_print_legend_header(char *header) {
#ifdef UNICODE
	print_legend_desc(coords.stat_x, 0, header, coords.stat_max, false);
#else
	print_legend_desc(coords.stat_x, 0, header, coords.stat_max);
#endif
}

void cr_print_legend_footer(char *footer) {
#ifdef UNICODE
	print_legend_desc(0, coords.text_y, footer, coords.footer_max, curses_mode == 3);
#else
	print_legend_desc(0, coords.text_y, footer, coords.footer_max);
#endif
}

void cr_print_hop(int at) {
	if (at < display_offset)
		return;
	cairo_t *cr = cairos[CR_LGND].cairo;
	PangoLayout *pl = cairos[CR_LGND].pango;

	// line
	set_source_rgb_func(cr, at);
	cairo_move_to(cr, 0, coords.line_y);
	cairo_rel_line_to(cr, cell.width, 0);
	cairo_stroke(cr);

	// hop
	cairo_set_source_rgb(cr, 0, 0, 0);
	char buf[8];
	sprintf(buf, "%2d.", first_hop + 1 + at);
	cairo_move_to(cr, coords.hop_x, coords.text_y);
	pango_layout_set_text(pl, buf, -1);
	pango_cairo_show_layout(cr, pl);
}

void cr_print_host(int at, int data, char *host, char *stat) {
	if (at < display_offset)
		return;

	cairo_t *cr = cairos[CR_LGND].cairo;
	PangoLayout *pl = cairos[CR_LGND].pango;
	if (data < 0)
		cairo_set_source_rgb(cr, 1, 0, 0);
	else
		cairo_set_source_rgb(cr, 0, 0, 0);

	cairo_move_to(cr, coords.host_x, coords.text_y);
	pango_layout_set_text(pl, host ? host : "???", -1);
	pango_cairo_show_layout(cr, pl);

	if (stat) {
		pango_layout_set_width(pl, (legend.width - coords.stat_x) * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);

		if (data < 0)
			cairo_set_source_rgb(cr, 1, 0, 0);
		else
			cairo_set_source_rgb(cr, 0, 0, 0);
		cairo_move_to(cr, coords.stat_x, coords.text_y);

		char *s;
#ifdef UNICODE
		if (curses_mode == 3) {
			if (wcslen((wchar_t*)stat) > coords.stat_max)
				*(((wchar_t*)stat) + coords.stat_max) = L'\0';
			static char mbs[1024];
			wcstombs(mbs, (wchar_t*)stat, 1024);
			s = mbs;
		} else
#endif
		{
			if (strlen(stat) > coords.stat_max)
				stat[coords.stat_max] = 0;
			s = stat;
		}
		pango_layout_set_text(pl, s, -1);
		pango_cairo_show_layout(cr, pl);

		pango_layout_set_width(pl, -1);
		pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
	}

	coords.text_y += coords.dy;
	coords.line_y += coords.dy;
}

static void rescale(int max) {
	datamax_prev = datamax;
	datamax = max + DATAMAX;
	draw_grid();
	scale_viewport();

	int i;
	for (i = 0; i < SPLINE_POINTS; i++) {
		int j;
		for (j = 0; j < hops; j++)
			if (y_point[i][j]) {
				double dy = ((double)(vp.height - y_point[i][j]) * datamax_prev) / datamax;
				y_point[i][j] = vp.height - POS_ROUND(dy);
			}
	}
}

void cr_redraw(int *data) {
	static int cycle_datamax;
	static long long cycle_period;
	if (!cycle_period)
		cycle_period = (long long)(USECONDS * (params->period * CYCLE_FACTOR) + 0.5);
	bool f_repaint = false;

	// timing
	static int remaining_time;
	struct timeval now, _tv;
	gettimeofday(&now, NULL);
	timersub(&now, &lasttime, &_tv);
	time_t dt = timer2usec(&_tv);
	int unclosed_dt = dt + remaining_time;
	lasttime = now;

	cycle_period -= dt;
	if (cycle_period < 0) {
		if (datamax > (cycle_datamax + DATAMAX))
			rescale(cycle_datamax);
		cycle_period = cycle_datamax = 0;
	}

	time_t dx = unclosed_dt / x_point_in_usec;
	remaining_time = unclosed_dt % x_point_in_usec;

	if (dx) {	// work
		// mean
		int i;
		for (i = 0; i < hops; i++)
			if (unclosed_data[i].count) {
				if (data[i] >= 0)
					data[i] = (data[i] + unclosed_data[i].data) / (unclosed_data[i].count + 1);
				else
					data[i] = unclosed_data[i].data / unclosed_data[i].count;
				unclosed_data[i].data = 0;
				unclosed_data[i].count = 0;
			}

		// max
		int current_max = 0;
		for (i = 0; i < hops; i++) {
			int d = data[i];
			if (d > current_max)
				current_max = d;
			y_point[0][i] = data_scale(d);
		}
		if (current_max > cycle_datamax)
			cycle_datamax = current_max;
		if (current_max > datamax)
			rescale(current_max);

		// shift
		if (dx < vp.width) {
			cairo_t *cr = cairos[CR_TEMP].cairo;
			cairo_set_source_surface(cr, cairos[CR_WORK].surface, -dx, 0);
			cairo_rectangle(cr, 0, 0, vp.width - dx, vp.height);
			cairo_fill(cr);
			swap_cairos(CR_WORK, CR_TEMP);
		} else
			dx = vp.width;

		// clearing
		int cl_dx = dx;
		if (params->graph_type == GRAPHTYPE_CURVE) {
			vp_layer.width = x_point[0] - x_point[1];
			cl_dx += vp_layer.width;
			vp_layer.x = vp.x + vp.width - vp_layer.width;
			cairo_t *cr = cairos[CR_LAYR].cairo;
			cairo_set_source_rgb(cr, 1, 1, 1);
			cairo_paint(cr);
		}
		cairo_t *cr = cairos[CR_WORK].cairo;
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, vp.width - cl_dx, 0, cl_dx, vp.height);
		cairo_fill(cr);

		if (params->graph_type == GRAPHTYPE_CURVE) {
			x_point[3] = x_point[2] - dx;
			x_point[2] = x_point[1] - dx;
			x_point[1] = x_point[0] - dx;
		} else if (params->graph_type == GRAPHTYPE_LINE)
			x_point[1] = x_point[0] - dx;

		graph_func(cr);	// fill new area
		f_repaint = true;
	} else {	// accumulate
		int i;
		for (i = 0; i < hops; i++)
			if (data[i] >= 0) {
				unclosed_data[i].data += data[i];
				unclosed_data[i].count++;
			}
	}


	if (unclosed_dt > USECONDS) {	// top: systime
		cairo_t* cr = cairos[CR_BASE].cairo;
		PangoLayout *pl = cairos[CR_BASE].pango;

		pango_layout_set_width(pl, vp.width * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_CENTER);
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, vp.x + coords.label_w, (vp.y - font_size) / 2, vp.width - coords.label_w, font_size);
		cairo_fill(cr);
		cairo_set_source_rgb(cr, 0, 0, 0);
		cairo_move_to(cr, vp.x, (vp.y - font_size) / 2);
		char buf[32];
		strftime(buf, sizeof(buf), "%c", localtime(&(now.tv_sec)));
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
		pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
		if (!f_repaint)
			f_repaint = true;
	}

	if ((dx && (unclosed_dt > USECONDS)) ||
		((tm_fmt == TM_MMSS) && (unclosed_dt > USECONDS)) ||
		((tm_fmt == TM_HHMM) && (unclosed_dt > 60 * USECONDS))) {	// bottom: x-axis tick marks

		cairo_t* cr = cairos[CR_BASE].cairo;
		PangoLayout *pl = cairos[CR_BASE].pango;

		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, vp.x - coords.label_w / 2, vp.y + vp.height, vp.width + coords.label_w, 3 * font_size);
		cairo_fill(cr);

		time_t actual_sec = now.tv_sec - POS_ROUND(wait_time * USECONDS) / USECONDS;
		if (now.tv_usec < (POS_ROUND(wait_time * USECONDS) % USECONDS))
			actual_sec--;
		int label_y = vp.y + vp.height + font_size / 2;
		int axis_dt = POS_ROUND((2.0 * params->period) / cell.y);
		time_t t = actual_sec - params->period;
		for (int i = 0, a = vp.x - coords.label_w / 2; i <= (cell.y / 2); i++, a += 2 * cell.width, t += axis_dt) {
			struct tm *ltm = localtime(&t);
			int lp, rp;
			if (tm_fmt == TM_MMSS) {
				lp = ltm->tm_min;
				rp = ltm->tm_sec;
			} else if (tm_fmt == TM_HHMM) {
				lp = ltm->tm_hour;
				rp = ltm->tm_min;
			} else
				lp = rp = 0;
			char buf[8];
			sprintf(buf, "%02d:%02d", lp, rp);
			cairo_set_source_rgb(cr, 1, 1, 1);
			cairo_rectangle(cr, a, label_y, coords.label_w, 2 * font_size);
			cairo_fill(cr);
			cairo_set_source_rgb(cr, 0, 0, 0);
			cairo_move_to(cr, a, label_y);
			pango_layout_set_text(pl, buf, -1);
			pango_cairo_show_layout(cr, pl);
		}
		if (!f_repaint)
			f_repaint = true;
	}

	if (f_repaint)
		cr_paint();
}

void cr_net_reset(int paused) {
	cairo_t *cr;
	int dx = vp.width;

	if (paused) {
		struct timeval now;
		gettimeofday(&now, NULL);
		if ((now.tv_sec - lasttime.tv_sec) < params->period) { // more precisely
			struct timeval _tv;
			timersub(&now, &lasttime, &_tv);
			dx = timer2usec(&_tv) / x_point_in_usec;
			// shift
			cairo_t *cr = cairos[CR_TEMP].cairo;
			cairo_save(cr);
			cairo_set_source_surface(cr, cairos[CR_WORK].surface, -dx, 0);
			cairo_rectangle(cr, 0, 0, vp.width - dx, vp.height);
			cairo_fill(cr);
			cairo_restore(cr);
			swap_cairos(CR_WORK, CR_TEMP);
		}
	}

	cr = cairos[CR_WORK].cairo;
	cairo_save(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, vp.width - dx, 0, dx, vp.height);
	cairo_fill(cr);
	cairo_restore(cr);

	cr_paint();

	int i;
	for (i = 0; i < SPLINE_POINTS; i++)
		memset(y_point[i], 0, maxTTL * sizeof(int));

	memset(unclosed_data, 0, maxTTL * sizeof(*unclosed_data));
}

void cr_close(void) {
	free(unclosed_data);
	int i;
	for (i = 0; i < SPLINE_POINTS; i++)
		free(y_point[i]);
	for (i = 0; i < CAIRO_SURFACES; i++) {
		if ((i == CR_LGND) && !params->enable_legend)
			continue;
		if ((i == CR_LAYR) && (params->graph_type != GRAPHTYPE_CURVE))
			continue;
		if (cairos[i].pango)
			g_object_unref(cairos[i].pango);
		if (cairos[i].font_desc)
			pango_font_description_free(cairos[i].font_desc);
		if (cairos[i].surface)
			cairo_surface_destroy(cairos[i].surface);
		if (cairos[i].cairo)
			cairo_destroy(cairos[i].cairo);
	}
	backend_destroy_window();
}

static void cr_resize(int width, int height, int shift) {
	if (((!base_window.width) || (!base_window.height)) ||
		((base_window.width == width) && (base_window.height == height)))
		return;
	if (!cairos[CR_BASE].cairo)
		return;
	GCDEBUG_MSG(("%sresize: (%d, %d) => (%d, %d)\n", shift ? "shift+" : "", base_window.width, base_window.height, width, height));
	if (shift) {
		GCDEBUG_MSG(("legend: (%d, %d, %d, %d) => ", legend.x, legend.y, legend.width, legend.height));
		legend.width += width - base_window.width;
		if (legend.width < 0)
			legend.width = 0;

		legend.height += height - base_window.height;
		if (legend.height < 0)
			legend.height = 0;
		GCDEBUG_MSG(("(%d, %d, %d, %d)\n", legend.x, legend.y, legend.width, legend.height));
		base_window.width = width;
		base_window.height = height;
		return;
	}
	base_window.width = width;
	base_window.height = height;

	if (shift)
		return;

	set_viewport_params();
	if (!cr_recreate_surfaces(1)) {
		fprintf(stderr, "cr_resize(): cr_recreate_surfaces() failed\n");
		return;
	}
	int i;
	for (i = 0; i < CAIRO_SURFACES; i++) {
		if ((i == CR_LGND) && !params->enable_legend)
			continue;
		pango_font_description_set_absolute_size(cairos[i].font_desc, font_size * PANGO_SCALE);
	}

	action = ACTION_RESIZE;

	// workarea rescaling
	cairo_t *cr = cairos[CR_WORK].cairo;
	cairo_save(cr);
	cairo_matrix_t m;
	cairo_matrix_init(&m, (double)vp.width / vp_prev.width, 0, 0,
		(double)vp.height / vp_prev.height, 0, 0);
	cairo_transform(cr, &m);
	cairo_set_source_surface(cr, cairos[CR_TEMP].surface, 0, 0);
	cairo_rectangle(cr, 0, 0, vp_prev.width, vp_prev.height);
	cairo_fill(cr);
	cairo_restore(cr);

	// spline point recalculation
	for (i = 0; i < SPLINE_POINTS; i++) {
		double x = x_point[i];
		double y = 0;
		cairo_matrix_transform_point(&m, &x, &y);
		x_point[i] = POS_ROUND(x);
		int j;
		for (j = 0; j < hops; j++)
			if (y_point[i][j]) {
				x = 0;
				y = y_point[i][j];
				cairo_matrix_transform_point(&m, &x, &y);
				y_point[i][j] = POS_ROUND(y);
			}
	}
	x_point[0] = vp.width;

	if (!cr_create_similar(CR_TEMP, CR_BASE, &vp)) {
		fprintf(stderr, "cr_resize(): cr_create_similar() failed\n");
		return;
	}
	draw_grid();
	cr_paint();
}

int cr_open(cr_params_t *cr_params) {
	params = cr_params;
	GCDEBUG_MSG(("params: type="));
	switch (params->graph_type) {
		case GRAPHTYPE_DOT:
			graph_func = graph_dot;
			GCDEBUG_MSG(("dot"));
			break;
		case GRAPHTYPE_LINE:
			graph_func = graph_line;
			GCDEBUG_MSG(("line"));
			break;
		case GRAPHTYPE_CURVE:
			graph_func = graph_curve;
			GCDEBUG_MSG(("curve"));
			break;
		default:
			params->graph_type = GRAPHTYPE_CURVE;
			graph_func = graph_curve;
			GCDEBUG_MSG(("curve"));
	}

	if (params->period)
		params->period *= GRIDLINES;
	else
		params->period = VIEWPORT_TIMEPERIOD;
	GCDEBUG_MSG((", period=%dsec", params->period));
	tm_fmt = (params->period < 3600) ? TM_MMSS : TM_HHMM;

	if (params->enable_legend)
		base_window.height *= 1.6;

	GCDEBUG_MSG((", legend=%d, multipath=%d, jitter_graph=%d\n", params->enable_legend, params->enable_multipath, params->jitter_graph));
	set_source_rgb_func = (maxTTL < cr_colors_max) ? set_source_rgb_dir : set_source_rgb_mod;

	if (backend_create_window(&base_window, cr_resize)) {
		if (!(unclosed_data = malloc(maxTTL * sizeof(*unclosed_data)))) {
			fprintf(stderr, "cr_open(): malloc failed\n");
			return 0;
		}
		memset(unclosed_data, 0, maxTTL * sizeof(*unclosed_data));

		int i;
		for (i = 0; i < SPLINE_POINTS; i++) {
			if (!(y_point[i] = malloc(maxTTL * sizeof(int)))) {
				fprintf(stderr, "cr_open(): malloc failed\n");
				return 0;
			}
			memset(y_point[i], 0, maxTTL * sizeof(int));
		}

		datamax = datamax_prev = DATAMAX;
		set_viewport_params();
	} else
		return 0;

	if (!cr_recreate_surfaces(0)) {
		fprintf(stderr, "cr_open(): cr_recreate_surfaces() failed\n");
		return 0;
	}
	int i;
	for (i = 0; i < CAIRO_SURFACES; i++) {
		if ((i == CR_LGND) && !params->enable_legend)
			continue;
		if ((i == CR_LAYR) && (params->graph_type != GRAPHTYPE_CURVE))
			continue;
		if (!cr_pango_open(i)) {
			fprintf(stderr, "cr_open(): cr_pango_open(%d) failed\n", i);
			return 0;
		}
	}
	draw_grid();
	cr_paint();

	gettimeofday(&lasttime, NULL);
	return 1;
}

int cr_dispatch_event(void) {
	int c = backend_dispatch_event();
#ifdef GCDEBUG
	if (c)
		printf("Key: 0x%02x (%c)\n", c, c);
#endif
	if (!c && action) {
		c = action;
		action = 0;
	}
	return c;
}

void cr_set_hops(int curr_hops, int min_hop) {
	if (curr_hops > hops)
		hops = curr_hops;
	first_hop = min_hop;
}

