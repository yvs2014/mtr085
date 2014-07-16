
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <math.h>
#include <cairo.h>
#include <pango/pangocairo.h>

#include "config.h"
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
	CR_TEMP
};
#define CAIRO_SURFACES	5

typedef struct {
	cairo_t *cairo;
	cairo_surface_t *surface;
	cairo_rectangle_int_t *rectangle;
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
#define CYCLE_FACTOR		1.0

extern int maxTTL;		// mtr.c
extern int display_mode;
extern int enablempls;
extern float WaitTime;
extern int display_offset;	// select.c

typedef void (*graph_func_t)(cairo_t *cr);
graph_func_t graph_func;

typedef void (*set_source_rgb_func_t)(cairo_t *cr, int i);
set_source_rgb_func_t set_source_rgb_func;

static cr_params_t params;

#define SPLINE_POINTS	4
static int x_point[SPLINE_POINTS];
static int *y_point[SPLINE_POINTS];

static cairo_rectangle_int_t base_window = { 0, 0, 780, 520 };
static cairo_rectangle_int_t vp;	// viewport
static cairo_rectangle_int_t vp_prev;
static cairo_rectangle_int_t grid;
static cairo_rectangle_int_t legend;
static cairo_rectangle_int_t cell; // x,y: horizontal/vertical gridlines

static int font_size;
static int tick_size;
static int datamax, datamax_prev;
static int hops, first_hop;
static int x_point_in_usec;
static int action;
static struct timeval lasttime;

typedef struct {
	int hop_x;
	int host_x;
	int stat_x;
	int text_y;
	int line_y;
	int dy;
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


int cr_check_status(cairo_t *cr, char *s) {
	int status = cairo_status(cr);
	if (status) {
		fprintf(stderr, "cr_check_status(): %s failed: %s\n", s, cairo_status_to_string(status));
		return 0;
	}
	return 1;
}

void swap_cairos(int ndx1, int ndx2) {
	cairos_t cairos_temp = cairos[ndx1];
	cairos[ndx1] = cairos[ndx2];
	cairos[ndx2] = cairos_temp;
}

int cr_create_similar(int ndx, int similar, cairo_rectangle_int_t *r) {
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

int cr_recreate_surfaces(int save) {
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
	if (params.enable_legend) {
		if (!cr_create_similar(CR_LGND, CR_BASE, &legend))
			return 0;
	}
	return save ? 1 : cr_create_similar(CR_TEMP, CR_BASE, &vp);
}

int cr_fill_base(int src) {
	cairo_t *dst = cairos[CR_BASE].cairo;
	cairo_set_source_surface(dst, cairos[src].surface, cairos[src].rectangle->x, cairos[src].rectangle->y);
	cairo_rectangle(dst, cairos[src].rectangle->x, cairos[src].rectangle->y,
			cairos[src].rectangle->width, cairos[src].rectangle->height);
	cairo_fill(dst);
	return cr_check_status(dst, "cr_fill_base()");
}

void cr_paint(void) {
	cr_fill_base(CR_WORK);
	cr_fill_base(CR_GRID);
	if (params.enable_legend)
		cr_fill_base(CR_LGND);
	backend_flush();
}

int cr_pango_open(int ndx) {
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

void set_viewport_params() {
	vp_prev = vp;

	double margin_right = MARGIN_RIGHT;
	double margin_bottom = MARGIN_BOTTOM;
	if (params.enable_legend)
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

	x_point_in_usec = (USECONDS * params.period) / vp.width;
	tick_size = cell.width / 8;
	font_size = POS_ROUND(FONT_SIZE * cell.height);

	grid.x = 0;
	grid.y = vp.y - font_size;
	grid.width = vp.x + vp.width + tick_size;
	grid.height = font_size + vp.height + tick_size;

	if (!x_point[0])
		x_point[0] = vp.width - 1;

	if (params.enable_legend) {
		legend.x = vp.x;
		legend.y = vp.y + vp.height + 3 * font_size;
		legend.width = vp.width;
		legend.height = vp.height;
	}

#ifdef GCDEBUG
	printf("window=(%d, %d), ", base_window.width, base_window.height);
	printf("viewport=(%d, %d, %d, %d), ", vp.x, vp.y, vp.width, vp.height);
	if (params.enable_legend)
		printf("legend=(%d, %d, %d, %d), ", legend.x, legend.y, legend.width, legend.height);
	printf("x-point=%dusec\n", x_point_in_usec);
#endif
}

void draw_grid(void) {
	cairo_t *cr = cairos[CR_GRID].cairo;
	PangoLayout *pl = cairos[CR_GRID].pango;

	cairo_save(cr);

	// x-axis, y-axis
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, vp.x, font_size - tick_size);
	cairo_rel_line_to(cr, 0, vp.height + tick_size);
	cairo_rel_line_to(cr, vp.width + tick_size, 0);

	// x-ticks, y-ticks
	int i, a;
	for (i = 0, a = font_size; i < cell.x; i++, a += cell.height) {
		cairo_move_to(cr, vp.x, a);
		cairo_rel_line_to(cr, -tick_size, 0);
	}
	for (i = 0, a = vp.x + cell.width; i < cell.y; i++, a += cell.width) {
		cairo_move_to(cr, a, grid.height);
		cairo_rel_line_to(cr, 0, -tick_size);
	}
	cairo_stroke(cr);

	// gridlines
	static const double dash[] = {1.0};
	cairo_set_dash(cr, dash, 1, 0);
	cairo_set_source_rgb(cr, GRID_RGB, GRID_RGB, GRID_RGB);
	for (i = 0, a = font_size; i < cell.x; i++, a += cell.height) {
		cairo_move_to(cr, vp.x, a);
		cairo_rel_line_to(cr, vp.width + tick_size, 0);
	}
	for (i = 0, a = vp.x + cell.width; i < cell.y; i++, a += cell.width) {
		cairo_move_to(cr, a, font_size - tick_size);
		cairo_rel_line_to(cr, 0, vp.height + tick_size);
	}
	cairo_stroke(cr);

	// y-labels
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
	for (i = 0, a = vp.height; i <= cell.x; i++, a -= cell.height) {
		cairo_move_to(cr, 0, a);
		sprintf(buf, fmt, coef1 * i);
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
	}

	cairo_restore(cr);
}

void scale_viewport(void) {
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

int data_scale(int data) {
	return data ? POS_ROUND(vp.height * (1 - (double)data / datamax)) : 0;
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

void graph_dot(cairo_t *cr) {
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

void graph_line(cairo_t *cr) {
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

double distance(int x0, int y0, int x1, int y1) {
	int dx1 = x1 - x0; int dy1 = y1 - y0;
	return sqrt(dx1 * dx1 + dy1 * dy1);
}

int centripetal(double d1, double q1, double d2, double q2, int p0, int p1, int p2) {
	double b = (d1*p0 - d2*p1 + (2*d1 + 3*q1*q2 + d2)*p2) / (3*q1*(q1 + q2));
	return POS_ROUND(b);
}

void graph_curve(cairo_t *cr) {
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
			cairo_line_to(cr, x3, y3);
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
	}

	int *tmp = y_point[3];
	y_point[3] = y_point[2];
	y_point[2] = y_point[1];
	y_point[1] = y_point[0];
	y_point[0] = tmp;
}

void print_legend_desc(int x, int y, char *desc, int desc_max) {
	if (desc) {
		cairo_t *cr = cairos[CR_LGND].cairo;
		PangoLayout *pl = cairos[CR_LGND].pango;
		pango_layout_set_width(pl, (legend.width - x) * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);

//		pango_layout_set_markup(pl, desc, -1);
		char *txt;
		PangoAttrList *attrs;
		pango_parse_markup(desc, -1, 0, &attrs, &txt, NULL, NULL);
		if (txt)
			if (strlen(txt) > desc_max)
				txt[desc_max] = 0;
		pango_layout_set_text(pl, txt, -1);
		pango_layout_set_attributes(pl, attrs);

		cairo_move_to(cr, x, y);
		cairo_set_source_rgb(cr, 0, 0, 0);
		pango_cairo_show_layout(cr, pl);
		pango_layout_set_attributes(pl, NULL);	// unref

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
	coords.hop_x = cell.width + w;
	coords.host_x = coords.hop_x + (w * 7) / 2;
	coords.stat_x = coords.host_x + (hostinfo_max + 1) * w;
	coords.stat_max = (legend.width - coords.stat_x) / w;

	if (coords.stat_max < 0)
		coords.stat_max = 0;
	if (coords.stat_max > params.cols_max)
		coords.stat_max = params.cols_max;
	coords.footer_max = legend.width / w;
	return coords.stat_max;
}

void cr_init_legend(void) {
	coords.text_y = coords.dy;
	coords.line_y = coords.text_y + font_size / 2 + 1;
	cairo_t *cr = cairos[CR_LGND].cairo;
	cairo_save(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_paint(cr);
	cairo_restore(cr);
}

void cr_print_legend_header(char *header) {
	print_legend_desc(coords.stat_x, 0, header, coords.stat_max);
}

void cr_print_legend_footer(char *footer) {
	print_legend_desc(0, coords.text_y, footer, coords.footer_max);
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
		if (strlen(stat) > coords.stat_max)
			stat[coords.stat_max] = 0;
		pango_layout_set_width(pl, (legend.width - coords.stat_x) * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);

		if (data < 0)
			cairo_set_source_rgb(cr, 1, 0, 0);
		else
			cairo_set_source_rgb(cr, 0, 0, 0);
		cairo_move_to(cr, coords.stat_x, coords.text_y);
		pango_layout_set_text(pl, stat, -1);
		pango_cairo_show_layout(cr, pl);

		pango_layout_set_width(pl, -1);
		pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
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
				double dy = ((double)(vp.height - y_point[i][j]) * datamax_prev) / datamax;
				y_point[i][j] = vp.height - POS_ROUND(dy);
			}
	}
}

void cr_redraw(int *data) {
	static int cycle_datamax;
	static int cycle_period;
	if (!cycle_period)
		cycle_period = POS_ROUND(USECONDS * params.period * CYCLE_FACTOR);

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

	cycle_period -= dt;
	if (cycle_period < 0) {
		if (datamax > (cycle_datamax + DATAMAX))
			rescale(cycle_datamax);
		cycle_period = cycle_datamax = 0;
	}

	int dx = unclosed_dt / x_point_in_usec;
	remaining_time = unclosed_dt % x_point_in_usec;

	cairo_t *cr;
	if (dx) {
		// shift
		if (dx < vp.width) {
			cr = cairos[CR_TEMP].cairo;
			cairo_set_source_surface(cr, cairos[CR_WORK].surface, -dx, 0);
			cairo_rectangle(cr, 0, 0, vp.width - dx, vp.height);
			cairo_fill(cr);
			swap_cairos(CR_WORK, CR_TEMP);
		} else
			dx = vp.width;

		// clearing
		cr = cairos[CR_WORK].cairo;
		cairo_save(cr);
		cairo_set_source_rgb(cr, 1, 1, 1);
		int cl_dx = dx;
		if (params.graph_type == GRAPHTYPE_CURVE)
			cl_dx += x_point[0] - x_point[1] + 1;
		cairo_rectangle(cr, vp.width - cl_dx, 0, cl_dx, vp.height);
		cairo_fill(cr);
		cairo_restore(cr);

		if (params.graph_type == GRAPHTYPE_CURVE) {
			x_point[3] = x_point[2] - dx;
			x_point[2] = x_point[1] - dx;
			x_point[1] = x_point[0] - dx;
		} else if (params.graph_type == GRAPHTYPE_LINE)
			x_point[1] = x_point[0] - dx;

		// fill new area
		cairo_save(cr);
		graph_func(cr);
		cairo_restore(cr);
	}

	cr = cairos[CR_BASE].cairo;
	PangoLayout *pl = cairos[CR_BASE].pango;

	// x-labels
	int label_w;
	pango_layout_set_width(pl, vp.width * PANGO_SCALE);
	pango_layout_set_alignment(pl, PANGO_ALIGN_CENTER);
	pango_layout_set_text(pl, "00:00", -1);
	pango_layout_get_pixel_size(pl, &label_w, NULL);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_rectangle(cr, vp.x, (vp.y - font_size) / 2, vp.width, font_size);	// systime
	cairo_rectangle(cr, vp.x - label_w / 2, vp.y + vp.height, vp.width + label_w, 3 * font_size);	// x-labels
	cairo_fill(cr);
	// top
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_move_to(cr, vp.x, (vp.y - font_size) / 2);
	char buf[128], *c;
	c = stpncpy(buf, asctime(localtime(&(now.tv_sec))), sizeof(buf));
	*(--c) = 0;
	pango_layout_set_text(pl, buf, -1);
	pango_cairo_show_layout(cr, pl);
	pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
	// bottom
	int label_y = vp.y + vp.height + font_size / 2;
	int a;
	time_t t;
	time_t actual_sec = now.tv_sec - POS_ROUND(WaitTime * USECONDS) / USECONDS;
	if (now.tv_usec < (POS_ROUND(WaitTime * USECONDS) % USECONDS))
		actual_sec--;
	dt = POS_ROUND((2.0 * params.period) / cell.y);
	for (i = 0, a = vp.x - label_w / 2, t = actual_sec - params.period; i <= (cell.y / 2); i++, a += 2 * cell.width, t += dt) {
		struct tm *ltm = localtime(&t);
		sprintf(buf, "%02d:%02d", ltm->tm_min, ltm->tm_sec);
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, a, label_y, label_w, 2 * font_size);
		cairo_fill(cr);
		cairo_set_source_rgb(cr, 0, 0, 0);
		cairo_move_to(cr, a, label_y);
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
	}

	cr_paint();
}

void cr_net_reset(int paused) {
	cairo_t *cr;
	int dx = vp.width;

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
}

void cr_close(void) {
	int i;
	for (i = 0; i < SPLINE_POINTS; i++)
		free(y_point[i]);
	for (i = 0; i < CAIRO_SURFACES; i++) {
		if ((i == CR_LGND) && !params.enable_legend)
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

void cr_resize(int width, int height, int shift) {
	if (((!base_window.width) || (!base_window.height)) ||
		((base_window.width == width) && (base_window.height == height)))
		return;
	if (!cairos[CR_BASE].cairo)
		return;
#ifdef GCDEBUG
	if (shift)
		printf("shift+");
	printf("resize: (%d, %d) => (%d, %d)\n", base_window.width, base_window.height, width, height);
#endif
	if (shift) {
#ifdef GCDEBUG
		printf("legend: (%d, %d, %d, %d) => ", legend.x, legend.y, legend.width, legend.height);
#endif
		legend.width += width - base_window.width;
		if (legend.width < 0)
			legend.width = 0;

		legend.height += height - base_window.height;
		if (legend.height < 0)
			legend.height = 0;
#ifdef GCDEBUG
		printf("(%d, %d, %d, %d)\n", legend.x, legend.y, legend.width, legend.height);
#endif
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
		if ((i == CR_LGND) && !params.enable_legend)
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
	x_point[0] = vp.width - 1;

	if (!cr_create_similar(CR_TEMP, CR_BASE, &vp)) {
		fprintf(stderr, "cr_resize(): cr_create_similar() failed\n");
		return;
	}
	draw_grid();
	cr_paint();
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
		base_window.height *= 1.6;

#ifdef GCDEBUG
	printf(", legend=%d, multipath=%d\n", params.enable_legend, params.enable_multipath);
#endif
	set_source_rgb_func = (maxTTL < cr_colors_max) ? set_source_rgb_dir : set_source_rgb_mod;

	if (backend_create_window(&base_window, cr_resize)) {
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
		if ((i == CR_LGND) && !params.enable_legend)
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

