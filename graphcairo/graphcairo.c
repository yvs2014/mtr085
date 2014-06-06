
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>
#include <cairo.h>
#include <pango/pangocairo.h>

#include "config.h"

// Cairo backends
#ifdef ENABLE_GRAPHCAIRO_XCB
#include "graphcairo-xcb.h"		// X Window System (XCB API)
#else
#error "No cairo backend defined."	// None
#endif

#include "graphcairo.h"

enum {
	CR_BASE,
	CR_GRID,
	CR_WORK,
	CR_TEMP,
	CR_LGND
};
#define CAIRO_SURFACES	5

typedef struct {
	cairo_surface_t *surface;
	cairo_t *cairo;
	PangoLayout *pango;
	PangoFontDescription *font_desc;
} cairos_t;
cairos_t cairos[CAIRO_SURFACES];

enum {
	GRAPHTYPE_NONE,
	GRAPHTYPE_DOT,
	GRAPHTYPE_LINE,
	GRAPHTYPE_CURVE
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
#define CHAR_BUFF_SZ		128
#define CYCLE_FACTOR		1.0

extern int maxTTL;		// mtr.c
extern int display_mode;
extern int enablempls;
extern int display_offset;	// select.c

typedef void (*graph_func_t)(cairo_t *cr);
graph_func_t graph_func;

typedef void (*set_source_rgb_func_t)(cairo_t *cr, int i);
set_source_rgb_func_t set_source_rgb_func;

static cr_params_t params;

#define SPLINE_POINTS	4
static int x_point[SPLINE_POINTS];
static int *y_point[SPLINE_POINTS];

typedef struct cr_rectangle_t {
	int x, y;	// left-top point
	int w, h;	// width, height
	int xw, yh;	// xw = x + w; yh = y + h;
} cr_rectangle_t;

static cr_rectangle_t base_window = { -1, -1, 780, 520, -1, -1 };	// base window
static cr_rectangle_t vp;	// viewport
static cr_rectangle_t vp_prev;
static cr_rectangle_t grid;	// x = cell width, y = cell height
				// w = horizontal gridline length, h = vertical gridline length (relative)
				// xw = N horizontal gridlines
				// yh = M vertical gridlines
static cr_rectangle_t legend;

enum {
	FONT_BASE,
	FONT_LGND
};
typedef struct {
	char* family;
	int size;
} font_params_t;
#define FONT_NO	2
static font_params_t font_params[FONT_NO];

static int datamax, datamax_prev;
static int cycle_period, cycle_datamax;	// period in usec
static int hops, first_hop;

static int tick_sz;

typedef struct {
	int hop_x;	
	int host_x;
	int stat_x;
	int text_y;
	int line_y;
	int dy;
	int ch_w;
	int ch_h;
} legend_coords_t;
static legend_coords_t coords;

static int action;

static struct timeval starttime;
static struct timeval lasttime;
static time_t now_in_sec;
static int x_point_in_usec;
static double line_width;

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


int cr_check_status(cairo_t *cr, char *s) {
	int status = cairo_status(cr);
	if (status) {
		fprintf(stderr, "ERROR: %s failed: %s\n", s, cairo_status_to_string(status));
		return 0;
	}
	return 1;
}

void swap_cairos(int ndx1, int ndx2) {
	cairos_t cairos_temp = cairos[ndx1];
	cairos[ndx1] = cairos[ndx2];
	cairos[ndx2] = cairos_temp;
}

int cr_create_similar(int ndx, int similar) {
	if (cairos[ndx].surface)
		cairo_surface_destroy(cairos[ndx].surface);
	if (cairos[ndx].cairo)
		cairo_destroy(cairos[ndx].cairo);

	if (similar >= 0)
		cairos[ndx].surface = cairo_surface_create_similar(cairo_get_target(cairos[similar].cairo),
			CAIRO_CONTENT_COLOR_ALPHA, base_window.w, base_window.h);
	else
		cairos[ndx].surface = backend_create_surface(base_window.w, base_window.h);

	if (!cairos[ndx].surface)
		return 0;
	cairos[ndx].cairo = cairo_create(cairos[ndx].surface);
	return cr_check_status(cairos[ndx].cairo, "cr_create_similar()");
}

// save ndx
// recreate: base, grid, work
int cr_recreate_surfaces(int ndx) {
	if (ndx >= 0)
		swap_cairos(CR_TEMP, ndx);
	if (!cr_create_similar(CR_BASE, -1))
		return 0;
	if (!cr_create_similar(CR_GRID, CR_BASE))
		return 0;
	if (!cr_create_similar(CR_WORK, CR_BASE))
		return 0;
	if (ndx < 0)
		if (!cr_create_similar(CR_TEMP, CR_BASE))
			return 0;
	if (!cr_create_similar(CR_LGND, CR_BASE))
		return 0;
	return 1;
}

int cr_paint(cairo_t *cr, cairo_surface_t *surf) {
	cairo_set_source_surface(cr, surf, 0, 0);
	cairo_paint(cr);
	return cr_check_status(cr, "cr_paint()");
}

void cr_paint_base(void) {
//	cairo_set_operator(cairos[CR_BASE], CAIRO_OPERATOR_XOR);
	if (cr_paint(cairos[CR_BASE].cairo, cairos[CR_WORK].surface))
	if (cr_paint(cairos[CR_BASE].cairo, cairos[CR_GRID].surface))
	if (cr_paint(cairos[CR_BASE].cairo, cairos[CR_LGND].surface))
		backend_flush();
}

int cr_pango_open(int ndx) {
	if (!(cairos[ndx].font_desc = pango_font_description_new()))
		return 0;

	font_params_t fp = (ndx == CR_LGND) ? font_params[FONT_LGND] : font_params[FONT_BASE];
	if (fp.family)
		pango_font_description_set_family(cairos[ndx].font_desc, fp.family);
	pango_font_description_set_absolute_size(cairos[ndx].font_desc, fp.size * PANGO_SCALE);

	if (!(cairos[ndx].pango = pango_cairo_create_layout(cairos[ndx].cairo)))
		return 0;
	pango_layout_set_font_description(cairos[ndx].pango, cairos[ndx].font_desc);

	return 1;
}

void set_viewport_params() {
	vp_prev = vp;

	double margin_right = MARGIN_RIGHT;
	double margin_bottom = MARGIN_BOTTOM;
	if (params.enable_legend)
		margin_bottom += 8;

	double d;
	d = (base_window.w * (GRIDLINES + MARGIN_TOP + margin_bottom)) /
	   	(base_window.h * (GRIDLINES + MARGIN_LEFT + margin_right)) + 0.2;
	if (d > 1) {
		grid.xw = GRIDLINES;
		grid.yh = GRIDLINES * POS_ROUND(d);
	} else {
		grid.yh = GRIDLINES;
		grid.xw = GRIDLINES * POS_ROUND(1 / d);
	}

	d = base_window.w / (MARGIN_LEFT + margin_right + grid.yh);
	grid.x = POS_ROUND(d);
	d = base_window.h / (MARGIN_TOP + margin_bottom + grid.xw);
	grid.y = POS_ROUND(d);

	vp.x = POS_ROUND(MARGIN_LEFT * grid.x);
	vp.y = POS_ROUND(MARGIN_TOP  * grid.y);
	vp.w = grid.yh * grid.x;
	vp.h = grid.xw * grid.y;
	vp.xw = vp.x + vp.w;
	vp.yh = vp.y + vp.h;

	x_point_in_usec = (USECONDS * params.period) / vp.w;
	tick_sz = grid.x / 8;

	grid.w =   vp.w + tick_sz;
	grid.h = -(vp.h + tick_sz);

	font_params[FONT_BASE].size = font_params[FONT_LGND].size = POS_ROUND(FONT_SIZE * grid.y);
	if (!x_point[0])
		x_point[0] = vp.xw - 1;

	if (params.enable_legend) {
		legend.x = vp.x;
		legend.y = vp.yh + FONT_SIZE * grid.y * 5 / 2;
		legend.w = vp.w;
		legend.h = vp.h;
		legend.xw = legend.x + legend.w;
		legend.yh = legend.y + legend.h;
	}

#ifdef GCDEBUG
	printf("window=(%d, %d), ", base_window.w, base_window.h);
	printf("viewport=(%d, %d, %d, %d), ", vp.x, vp.y, vp.w, vp.h);
	printf("legend=(%d, %d, %d, %d), ", legend.x, legend.y, legend.w, legend.h);
	printf("x-point=%dusec\n", x_point_in_usec);
#endif
}

void draw_grid(void) {
	cairo_t *cr = cairos[CR_GRID].cairo;
	PangoLayout *pl = cairos[CR_GRID].pango;

	cairo_save(cr);

	// x-axis, y-axis
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, vp.x, vp.yh);
	cairo_rel_line_to(cr, 0, grid.h);
	cairo_move_to(cr, vp.x, vp.yh);
	cairo_rel_line_to(cr, grid.w, 0);
	cairo_stroke(cr);

	// x-ticks, y-ticks
	int i, a;
	for (i = 0, a = vp.yh - grid.y; i < grid.xw; i++, a -= grid.y) {
		cairo_move_to(cr, vp.x, a);
		cairo_rel_line_to(cr, -tick_sz, 0);
	}
	for (i = 0, a = vp.x + grid.x; i < grid.yh; i++, a += grid.x) {
		cairo_move_to(cr, a, vp.yh);
		cairo_rel_line_to(cr, 0, tick_sz);
	}
	cairo_stroke(cr);

	// gridlines
	static const double dash[] = {1.0};
	static int dash_len  = sizeof(dash) / sizeof(dash[0]);
	cairo_set_line_width(cr, 1);
	cairo_set_dash(cr, dash, dash_len, 0);
	cairo_set_source_rgb(cr, GRID_RGB, GRID_RGB, GRID_RGB);
	for (i = 0, a = vp.yh - grid.y; i < grid.xw; i++, a -= grid.y) {
		cairo_move_to(cr, vp.x, a);
		cairo_rel_line_to(cr, grid.w, 0);
	}
	for (i = 0, a = vp.x + grid.x; i < grid.yh; i++, a += grid.x) {
		cairo_move_to(cr, a, vp.yh);
		cairo_rel_line_to(cr, 0, grid.h);
	}
	cairo_stroke(cr);


	// y-labels
	int pl_width = vp.x - 3 * tick_sz;
	pango_layout_set_width(pl, pl_width * PANGO_SCALE);
	pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, 0, 0, pl_width, vp.yh);
	cairo_fill(cr);
	char fmt[CHAR_BUFF_SZ];
	snprintf(fmt, sizeof(fmt), "%%%d.1f", TICKLABEL_LEN);
	cairo_set_source_rgb(cr, 0, 0, 0);
	double coef1 = (double)datamax / (grid.xw * 1000);	// 1000: usec -> msec
	for (i = 0, a = vp.yh - font_params[FONT_BASE].size; i <= grid.xw; i++, a -= grid.y) {
		char buf[CHAR_BUFF_SZ];
		cairo_move_to(cr, 0, a);
		snprintf(buf, sizeof(buf), fmt, coef1 * i);
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
	}

	cairo_restore(cr);
}

int scale_viewport(void) {
	cairo_t *cr = cairos[CR_TEMP].cairo;
	cairo_save(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, vp.x, vp.y, vp.w, vp.h);
	cairo_fill(cr);

	double sy = (double)datamax_prev / datamax;
	cairo_matrix_t m;
	cairo_matrix_init(&m, 1, 0, 0, sy, 0, vp.yh - sy * vp.yh);
	cairo_transform(cr, &m);
	cairo_set_source_surface(cr, cairos[CR_WORK].surface, 0, 0);
	cairo_rectangle(cr, vp.x, vp.y, vp.w, vp.h);
	cairo_fill(cr);
	cairo_restore(cr);

	if (!cr_check_status(cr, "scale_viewport()"))
		return 0;
	swap_cairos(CR_WORK, CR_TEMP);
	return 1;
}

int data_scale(int data) {
	if (data) {
		double dy = ((double)vp.h * data) / datamax;
		return (vp.yh - POS_ROUND(dy));
	}
	return 0;
}

void set_source_rgb_mod(cairo_t *cr, int i) {
	int ndx = i % cr_colors_max;
	cairo_set_source_rgb(cr, cr_colors[ndx][0], cr_colors[ndx][1], cr_colors[ndx][2]);
}
void set_source_rgb_dir(cairo_t *cr, int i) {
	cairo_set_source_rgb(cr, cr_colors[i][0], cr_colors[i][1], cr_colors[i][2]);	// maxTTL l.e. colors_max
}

void draw_dot(cairo_t *cr, int i, int x0, int y0) {
	set_source_rgb_func(cr, i);
	cairo_move_to(cr, x_point[0], y0);
	cairo_close_path(cr);
	cairo_stroke(cr);
}

void draw_line(cairo_t *cr, int i, int x0, int y0, int x1, int y1) {
	set_source_rgb_func(cr, i);
	cairo_move_to(cr, x0, y0);
	cairo_line_to(cr, x1, y1);
	cairo_stroke(cr);
}

int graph_net_min(void) {
	return (display_offset < hops) ? display_offset : (hops - 1);
}

void graph_dot(cairo_t *cr) {
	cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
	cairo_set_line_width(cr, DOT_SIZE);
	int i;
	for (i = graph_net_min(); i < hops; i++) {
		int x0 = x_point[0]; int y0 = y_point[0][i];
		if (y0)
			draw_dot(cr, i, x0, y0);
	}
}

void graph_line(cairo_t *cr) {
	int i;
	for (i = graph_net_min(); i < hops; i++) {
		int x0 = x_point[0]; int y0 = y_point[0][i];
		int x1 = x_point[1]; int y1 = y_point[1][i];
		if (y0 && y1)
			draw_line(cr, i, x1, y1, x0, y0);
		else if (y0) {
			cairo_save(cr);
			cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
			cairo_set_line_width(cr, DOT_SIZE);
			draw_dot(cr, i, x0, y0);
			cairo_restore(cr);
		}
	}
	int *tmp = y_point[1];
	y_point[1] = y_point[0];
	y_point[0] = tmp;
}

double distance(int x0, int y0, int x1, int y1) {
	int dx1 = x1 - x0; int dy1 = y1 - y0;
	return sqrt(dx1 * dx1 + dy1 * dy1);
}

int centripetal(double d1, double q1, double d2, double q2, int p0, int p1, int p2) {
	double b = (d1*p0 - d2*p1 + (2*d1 + 3*q1*q2 + d2)*p2) / (3*q1*(q1 + q2));
	int r = POS_ROUND(b);
	return r;
}

void graph_curve(cairo_t *cr) {
	int i;
	for (i = graph_net_min(); i < hops; i++) {
		// note: (P0, P1, P2, P3) eq (point[3], point[2],_point[1], point[0])
		int x3 = x_point[0]; int y3 = y_point[0][i];
		int x2 = x_point[1]; int y2 = y_point[1][i];
		int x1 = x_point[2]; int y1 = y_point[2][i];
		int x0 = x_point[3]; int y0 = y_point[3][i];

		if (y0 && y1 && y2 && y3) {
			// previous line clearing
			cairo_set_source_rgb(cr, 1, 1, 1);
			cairo_set_line_width(cr, line_width + 1);
			cairo_move_to(cr, x1, y1);
			cairo_line_to(cr, x2, y2);
			cairo_stroke(cr);
			cairo_set_line_width(cr, line_width);

			int ax, ay, bx, by;
			double d1 = distance(x0, y0, x1, y1);
			double d2 = distance(x1, y1, x2, y2);
			double d3 = distance(x2, y2, x3, y3);
			if ((d1 != 0) && (d2 != 0) && (d3 != 0)) {
// Centripetal Catmull-Rom spline:
//
//	     d1*p2 - d2*p0 + (2d1 + 3 * d1^1/2 * d2^1/2 + d2)*p1
//	b1 = ---------------------------------------------------
//	     3d1^1/2 * (d1^1/2 + d2^1/2)
//
//	     d3*p1 - d2*p3 + (2d3 + 3 * d3^1/2 * d2^1/2 + d2)*p2
//	b2 = ---------------------------------------------------
//	     3d3^1/2 * (d3^1/2 + d2^1/2)
//
				double q1 = sqrt(d1);
				double q2 = sqrt(d2);
				double q3 = sqrt(d3);
				ax = centripetal(d1, q1, d2, q2, x2, x0, x1);
				ay = centripetal(d1, q1, d2, q2, y2, y0, y1);
				bx = centripetal(d3, q3, d2, q2, x1, x3, x2);
				by = centripetal(d3, q3, d2, q2, y1, y3, y2);
			} else {
// Uniform Catmull-Rom spline (unparameterized implemenatation):
//	b1 = p1 + (p2 - p0) / 6
//	b2 = p2 - (p3 - p1) / 6
				ax = x1 + (x2 - x0) / 6;
				ay = y1 + (y2 - y0) / 6;
				bx = x2 - (x3 - x1) / 6;
				by = y2 - (y3 - y1) / 6;
			}
	
			set_source_rgb_func(cr, i);
			cairo_move_to(cr, x1, y1);
			cairo_curve_to(cr, ax, ay, bx, by, x2, y2);
			cairo_line_to(cr, x3, y3);
			cairo_stroke(cr);
		} else if (y0 && y1)
			draw_line(cr, i, x0, y0, x1, y1);
		else if (y0) {
			cairo_save(cr);
			cairo_set_line_cap(cr, CAIRO_LINE_CAP_ROUND);
			cairo_set_line_width(cr, DOT_SIZE);
			draw_dot(cr, i, x0, y0);
			cairo_restore(cr);
		}
	}

	int *tmp = y_point[3];
	y_point[3] = y_point[2];
	y_point[2] = y_point[1];
	y_point[1] = y_point[0];
	y_point[0] = tmp;
}

void print_legend_description(int x, int y, char *desc) {
	cairo_t *cr = cairos[CR_LGND].cairo;
	PangoLayout *pl = cairos[CR_LGND].pango;
	cairo_move_to(cr, x, y);
	cairo_set_source_rgb(cr, 0, 0, 0);
	pango_layout_set_markup(pl, desc, -1);
	pango_cairo_show_layout(cr, pl);
	pango_layout_set_attributes(pl, NULL);
}

int cr_get_cols(int len) {
	static int hostinfo_len;
	if (len)
		hostinfo_len = len;

	coords.hop_x = legend.x + grid.x + coords.ch_w;
	coords.host_x = coords.hop_x + (7 * coords.ch_w) / 2;
	if (hostinfo_len)
		coords.stat_x = coords.host_x + (hostinfo_len + 1) * coords.ch_w;
	int cols = (legend.xw - coords.stat_x) / coords.ch_w;
	if (cols > params.cols_max) {
		coords.stat_x = legend.xw - ((legend.xw - coords.stat_x) * params.cols_max) / cols; // right justify
		cols = params.cols_max;
	}
	return cols;
}

void cr_restat(char *header) {
	cairo_t *cr = cairos[CR_LGND].cairo;
	PangoLayout *pl = cairos[CR_LGND].pango;

	// misc
	pango_layout_set_text(pl, ".", -1);
	pango_layout_get_pixel_size(pl, &coords.ch_w, &coords.ch_h);
	coords.dy = (coords.ch_h * 3) / 2;
	coords.hop_x = legend.x + grid.x + coords.ch_w;
	coords.host_x = coords.hop_x + (coords.ch_w * 7) / 2;

	// legend clearing
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, legend.x, legend.y + coords.dy,
		legend.w + MARGIN_RIGHT * grid.x, legend.h - coords.dy);
	cairo_fill(cr);

	if (header) {
		pango_layout_set_markup(pl, header, -1);
		int stat_w;
		pango_layout_get_pixel_size(pl, &stat_w, NULL);

		if (display_mode)
			cr_get_cols(0);
		else
			coords.stat_x = legend.xw - stat_w;

		// legend header
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, legend.x, legend.y, legend.w, (coords.ch_h * 3) / 2);
		cairo_fill(cr);
		print_legend_description(coords.stat_x, legend.y, header);
	}
}

void cr_init_print(void) {
	coords.text_y = legend.y + coords.dy;
	coords.line_y = coords.text_y + font_params[FONT_LGND].size / 2 + 1;

	// legend clearing
	cairo_t *cr = cairos[CR_LGND].cairo;
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, legend.x, legend.y + coords.dy, legend.w, legend.h - coords.dy);
	cairo_fill(cr);
}

void cr_print_legend_footer(char *footer) {
	print_legend_description(coords.host_x, coords.text_y, footer);
//	print_legend_description(coords.stat_x, coords.text_y, footer);
}

void cr_print_hop(int at) {
	if (at < graph_net_min())
		return;
	cairo_t *cr = cairos[CR_LGND].cairo;
	PangoLayout *pl = cairos[CR_LGND].pango;

	// line
	set_source_rgb_func(cr, at);
	cairo_move_to(cr, legend.x, coords.line_y);
	cairo_rel_line_to(cr, grid.x, 0);
	cairo_stroke(cr);

	// hop
	cairo_set_source_rgb(cr, 0, 0, 0);
	char buf[8];
	snprintf(buf, sizeof(buf), "%2d.", first_hop + 1 + at);
	cairo_move_to(cr, coords.hop_x, coords.text_y);
	pango_layout_set_text(pl, buf, -1);
	pango_cairo_show_layout(cr, pl);
}

void cr_print_host(int at, int data, char *host, char *stat) {
	if (at < graph_net_min())
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
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, coords.stat_x, coords.text_y, legend.xw - coords.stat_x, coords.dy);
		cairo_fill(cr);
		if (data < 0)
			cairo_set_source_rgb(cr, 1, 0, 0);
		else
			cairo_set_source_rgb(cr, 0, 0, 0);
		cairo_move_to(cr, coords.stat_x, coords.text_y);
		pango_layout_set_text(pl, stat, -1);
		pango_cairo_show_layout(cr, pl);
	}

	coords.text_y += coords.dy;
	coords.line_y += coords.dy;
}

void rescale(int max) {
	datamax_prev = datamax;
	datamax = max + DATAMAX;
	draw_grid();
	scale_viewport();

	int i;
	for (i = 0; i < SPLINE_POINTS; i++) {
		int j;
		for (j = 0; j < hops; j++)
			if (y_point[i][j]) {
				double dy = ((double)(vp.yh - y_point[i][j]) * datamax_prev) / datamax;
				y_point[i][j] = vp.yh - POS_ROUND(dy);
			}
	}
}

void cr_redraw(int *data) {
	// max
	int i, current_max = 0;
	for (i = 0; i < hops; i++)
		if (data[i] > current_max)
			current_max = data[i];

	if (current_max > cycle_datamax)
		cycle_datamax = current_max;
	if (current_max > datamax)
		rescale(current_max);

	for (i = 0; i < hops; i++)
		y_point[0][i] = data_scale(data[i]);

	int dt;
	static int remaining_time;
	struct timeval now;
	gettimeofday(&now, NULL);
	dt = (now.tv_sec - lasttime.tv_sec) * USECONDS + (now.tv_usec - lasttime.tv_usec);
	int unclosed_dt = dt + remaining_time;
	lasttime = now;
	now_in_sec = now.tv_sec;

	cycle_period -= dt;
	if (cycle_period < 0) {
		if (datamax > (cycle_datamax + DATAMAX))
			rescale(cycle_datamax);
		cycle_period = POS_ROUND(USECONDS * params.period * CYCLE_FACTOR);
		cycle_datamax = 0;
	}

	int dx = unclosed_dt / x_point_in_usec;
	remaining_time = unclosed_dt % x_point_in_usec;

	cairo_t *cr;
	if (dx) {
		// shift
		if (dx < vp.w) {
			cr = cairos[CR_TEMP].cairo;
			cairo_save(cr);
			cairo_set_source_surface(cr, cairos[CR_WORK].surface, -dx, 0);
			cairo_rectangle(cr, vp.x, vp.y, vp.w - dx, vp.h);
			cairo_fill(cr);
			cairo_restore(cr);
			swap_cairos(CR_WORK, CR_TEMP);
		} else
			dx = vp.w;

		// clearing
		cr = cairos[CR_WORK].cairo;
		cairo_save(cr);
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, vp.xw - dx, vp.y, dx + grid.x, vp.h);
		cairo_fill(cr);
		cairo_restore(cr);

		if (params.graph_type == GRAPHTYPE_CURVE) {
			if (x_point[2] > 0)
				x_point[3] = x_point[2] - dx;
			if (x_point[1] > 0)
				x_point[2] = x_point[1] - dx;
			if (x_point[0] > 0)
				x_point[1] = x_point[0] - dx;
			line_width = cairo_get_line_width(cr);
		} else if (params.graph_type == GRAPHTYPE_LINE)
			if (x_point[0] > 0)
				x_point[1] = x_point[0] - dx;

		// fill new area
		cairo_save(cr);
		graph_func(cr);
		cairo_restore(cr);
	} else
		cr = cairos[CR_WORK].cairo;

	// x-labels
	PangoLayout *pl = cairos[CR_WORK].pango;
	int label_w;
	pango_layout_set_width(pl, vp.w * PANGO_SCALE);
	pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
	pango_layout_set_text(pl, "00:00", -1);
	pango_layout_get_pixel_size(pl, &label_w, NULL);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, vp.x, 0, vp.w, grid.y);	// systime clearing
	cairo_fill(cr);
	cairo_rectangle(cr, vp.x - label_w / 2, vp.yh, vp.w + label_w, (font_params[FONT_BASE].size * 3) / 2);	// x-labels clearing
	cairo_fill(cr);
	// top
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, base_window.w / 2 - 2 * grid.x, (grid.y - font_params[FONT_BASE].size)/ 2);
	struct tm *ltm = localtime(&now_in_sec);
	char buf[CHAR_BUFF_SZ], *c;
	c = stpncpy(buf, asctime(ltm), sizeof(buf));
	*(--c) = 0;
	pango_layout_set_text(pl, buf, -1);
	pango_cairo_show_layout(cr, pl);
	// bottom
	int label_y = vp.yh + font_params[FONT_BASE].size / 2;
	int a;
	time_t t;
	dt = POS_ROUND((2.0 * params.period) / grid.yh);
	for (i = 0, a = vp.xw - label_w / 2, t = now_in_sec; i <= (grid.yh / 2); i++, a -= 2 * grid.x, t -= dt) {
		ltm = localtime(&t);
		cairo_move_to(cr, a, label_y);
		snprintf(buf, sizeof(buf), "%02d:%02d", ltm->tm_min, ltm->tm_sec);
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
	}

	cr_paint_base();
}

void cr_net_reset(int paused) {
	cairo_t *cr;
	int dx = vp.w;

	if (paused) {
		struct timeval now;
		gettimeofday(&now, NULL);
		int dt = now.tv_sec - lasttime.tv_sec;
		if (dt < params.period)	{ // more precisely
			dx = (dt * USECONDS + (now.tv_usec - lasttime.tv_usec)) / x_point_in_usec;
			// shift
			cairo_t *cr = cairos[CR_TEMP].cairo;
			cairo_save(cr);
			cairo_set_source_surface(cr, cairos[CR_WORK].surface, -dx, 0);
			cairo_rectangle(cr, vp.x, vp.y, vp.w - dx, vp.h);
			cairo_fill(cr);
			cairo_restore(cr);
			swap_cairos(CR_WORK, CR_TEMP);
		}
	}

	cr = cairos[CR_WORK].cairo;
	cairo_save(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, vp.xw - dx, vp.y, dx, vp.h);
	cairo_fill(cr);
	cairo_restore(cr);

	cr_paint_base();

	int i;
	for (i = 0; i < SPLINE_POINTS; i++)
		memset(y_point[i], 0, maxTTL * sizeof(int));
}

void cr_close(void) {  
	int i;
	for (i = 0; i < SPLINE_POINTS; i++)
		free(y_point[i]);
	for (i = 0; i < (sizeof(cairos) / sizeof(cairos[0])); i++) {
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

void cr_resize(int width, int height, int shift) {
	if ((base_window.w == width) && (base_window.h == height))
		return;
	if (!cairos[CR_BASE].cairo)
		return;
#ifdef GCDEBUG
	if (shift)
		printf("shift+");
	printf("resize: (%d, %d) => (%d, %d)\n", base_window.w, base_window.h, width, height);
#endif
	if (shift) {
#ifdef GCDEBUG
		printf("legend: (%d, %d, %d, %d) => ", legend.x, legend.y, legend.w, legend.h);
#endif
		legend.w += width - base_window.w;
		if (legend.w < 0)
			legend.w = 0;
		legend.xw = legend.x + legend.w;

		legend.h += height - base_window.h;
		if (legend.h < 0)
			legend.h = 0;
		legend.yh = legend.y + legend.h;
#ifdef GCDEBUG
		printf("(%d, %d, %d, %d)\n", legend.x, legend.y, legend.w, legend.h);
#endif
		base_window.w = width;
		base_window.h = height;
		return;
	}
	base_window.w = width;
	base_window.h = height;

	if (shift)
		return;

	set_viewport_params();
	if (!cr_recreate_surfaces(CR_WORK))
		return;
	action = ACTION_RESIZE;

	// workarea rescaling
	cairo_t *cr = cairos[CR_WORK].cairo;
	cairo_matrix_t m;

	cairo_save(cr);
	double sx = (double)vp.w / vp_prev.w;
	double sy = (double)vp.h / vp_prev.h;
	cairo_matrix_init(&m, sx, 0, 0, sy, vp.x - sx * vp_prev.x, vp.y - sy * vp_prev.y);
	cairo_transform(cr, &m);
	cairo_set_source_surface(cr, cairos[CR_TEMP].surface, 0, 0);
	cairo_rectangle(cr, vp_prev.x, vp_prev.y, vp_prev.w, vp_prev.h);
	cairo_fill(cr);
	cairo_restore(cr);

	// spline point recalculation
	int i;
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
	x_point[0] = vp.xw - 1;

	struct timeval now;
	gettimeofday(&now, NULL);
	int dt = now.tv_sec - starttime.tv_sec;
	if (dt < params.period) { // more precisely
		int dx = vp.w - (dt * USECONDS + (now.tv_usec - starttime.tv_usec)) / x_point_in_usec;
		if (dx > 0) {	// workarea clearing
			cairo_save(cr);
			cairo_set_source_rgb(cr, 1, 1, 1);
			cairo_rectangle(cr, vp.x, vp.y, dx, vp.h);
			cairo_fill(cr);
			cairo_restore(cr);
		}
	}

	// outside
	cairo_save(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, 0, 0, vp.x, base_window.w);
	cairo_rectangle(cr, vp.x, 0, base_window.w - vp.x, vp.y);
	cairo_rectangle(cr, vp.xw, vp.y, base_window.w - vp.xw, base_window.h - vp.y);
	cairo_rectangle(cr, vp.x, vp.yh, vp.w, base_window.h - vp.yh);
	cairo_fill(cr);
	cairo_restore(cr);

	if (!cr_create_similar(CR_TEMP, CR_BASE))
		return;
	draw_grid();
	cr_paint_base();
}

int cr_open(cr_params_t *cr_params) {
	if (cr_params)
		params = *cr_params;
#ifdef GCDEBUG
	printf("params: type=");
#endif
	switch (params.graph_type) {
		case GRAPHTYPE_DOT:
			graph_func = graph_dot;
#ifdef GCDEBUG
			printf("dot");
#endif
			break;
		case GRAPHTYPE_LINE:
			graph_func = graph_line;
#ifdef GCDEBUG
			printf("line");
#endif
			break;
		case GRAPHTYPE_CURVE:
			graph_func = graph_curve;
#ifdef GCDEBUG
			printf("curve");
#endif
			break;
		default:
			params.graph_type = GRAPHTYPE_CURVE;
			graph_func = graph_curve;
#ifdef GCDEBUG
			printf("curve");
#endif
	}

	if (params.period)
		params.period *= GRIDLINES;
	else
		params.period = VIEWPORT_TIMEPERIOD;
#ifdef GCDEBUG
	printf(", period=%dsec", params.period);
#endif

	if (params.enable_legend)
		base_window.h *= 1.6;

#ifdef GCDEBUG
	printf(", legend=%d, multipath=%d\n", params.enable_legend, params.enable_multipath);
#endif
	font_params[FONT_BASE].family = "monospace";
	font_params[FONT_LGND].family = font_params[FONT_BASE].family;

	set_source_rgb_func = (maxTTL < cr_colors_max) ? set_source_rgb_dir : set_source_rgb_mod;

	if (backend_create_window(base_window.w, base_window.h, cr_resize)) {
		int i;
		for (i = 0; i < SPLINE_POINTS; i++) {
   			if (!(y_point[i] = malloc(maxTTL * sizeof(int)))) {
				fprintf(stderr, "cr_open(): malloc failed\n");
				return 0;
			}
			memset(y_point[i], 0, maxTTL * sizeof(int));
		}
		datamax = datamax_prev = DATAMAX;
		cycle_period = POS_ROUND(USECONDS * params.period * CYCLE_FACTOR);
		cycle_datamax = 0;
		set_viewport_params();
	} else
		return 0;

	if (!cr_recreate_surfaces(-1))
		return 0;
	int i;
	for (i = 0; i < (sizeof(cairos) / sizeof(cairos[0])); i++)
		if (!cr_pango_open(i))
			return 0;
	draw_grid();

	gettimeofday(&starttime, NULL);
	lasttime = starttime;
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

	double s = (double)vp.h / (2 * (hops + 1));
	int sz = POS_ROUND(s);
	font_params[FONT_LGND].size = (sz < font_params[FONT_BASE].size) ? sz : font_params[FONT_BASE].size;
}

