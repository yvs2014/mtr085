
#include <math.h>
#include <cairo.h>
#include <pango/pangocairo.h>

#include "config.h"

#ifdef FC_FINI
#include <fontconfig/fontconfig.h>
#endif

#include "mtr.h"
#include "mtr-curses.h"
#include "net.h"
#include "graphcairo.h"
#include "graphcairo-backend.h"
#include "macros.h"

// Cairo backends: XCB or Xlib
#ifndef GRAPHCAIRO_XCB
#ifndef GRAPHCAIRO_XLIB
#error "No cairo backend defined"
#endif
#endif

enum { BASE, WORK, GRID, LEGEND, LAYER, TEMP };
#define SKINS	6

typedef struct {
  cairo_t *cairo;
  cairo_surface_t *surface;
  cairo_rectangle_int_t *rect;
  PangoLayout *pango;
  PangoFontDescription *font;
} skin_t;
static skin_t skins[SKINS];

enum { GT_NONE, GT_DOT, GT_LINE, GT_CURVE };
enum { TM_MMSS, TM_HHMM };

#define DATAMAX_MIN   5000  // in usec (y-axis)
#define DATAMAX_EXTRA    5  // in % (y-axis)
#define VIEWPORT_PERIOD	60  // in sec  (x-axis)
#define MARGIN_LEFT     2.0 // in dx
#define MARGIN_RIGHT    1.3 // in dx
#define MARGIN_TOP      1.0 // in dy
#define MARGIN_BOTTOM   1.3 // in dy
#define GRID_RGB        0.7
#define FONT_SIZE       0.3 // in cells
#define TICKLABEL_LEN   5
#define GRIDLINES       10
#define DOT_SIZE        3
#define CYCLE_FACTOR    1.0

typedef void (*graph_func_t)(cairo_t *cr);
static graph_func_t graph_func;

typedef void (*set_source_rgb_func_t)(cairo_t *cr, int i);
static set_source_rgb_func_t set_source_rgb_func;

static cr_params_t *params;

#define SPLINE_POINTS	4
static int x_point[SPLINE_POINTS];
static int* y_point[SPLINE_POINTS];
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
static long datamax, datamax_prev;
static int hops, first_hop;
static int x_mil; // x-axis magnitude multiplied by MIL
static int action;
static int tm_fmt;
static struct timespec last;

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


static bool status(cairo_t *c, const char *fn) {
  int rc = cairo_status(c);
  if (rc)
    WARNX_("%s: %s", fn, cairo_status_to_string(rc));
  return rc ? false : true;
}

static inline void swap(int a, int b) { skin_t t = skins[a]; skins[a] = skins[b]; skins[b] = t; }

static bool clone(int from, int to, cairo_rectangle_int_t *r) {
  skin_t *dst = &skins[to];
  cairo_surface_t *src = (from < 0) ? NULL : skins[from].surface;
  cairo_surface_t *surface = src
    ? cairo_surface_create_similar(src, CAIRO_CONTENT_COLOR_ALPHA, r->width, r->height)
    : backend_create_surface(r->width, r->height);
  if (!surface) {
    WARNX("surface creation failed");
    return false;
  }
  cairo_t *cairo = cairo_create(surface);
  bool re = status(cairo, __FUNCTION__);
  if (re) {
    dst->rect = r;
    if (dst->surface)
      cairo_surface_destroy(dst->surface);
    dst->surface = surface;
    if (dst->cairo)
      cairo_destroy(dst->cairo);
    dst->cairo = cairo;
  } else
    cairo_surface_destroy(surface);
  return re;
}

static bool create_surfaces(int save) {
  if (save)
    swap(WORK, TEMP);
  if (!clone(-1, BASE, &base_window))
    return false;
  cairo_set_source_rgb(skins[BASE].cairo, 1, 1, 1);
  cairo_paint(skins[BASE].cairo);
  if (!clone(BASE, WORK, &vp))
    return false;
  if (!clone(BASE, GRID, &grid))
    return false;
  if (params->enable_legend && !clone(BASE, LEGEND, &legend))
    return false;
  if ((params->graph_type == GT_CURVE) && !clone(BASE, LAYER, &vp_layer))
    return false;
  if (!save && !clone(BASE, TEMP, &vp))
    return false;
  return true;
}

static bool paint_on_base(int ndx) {
  skin_t *src = &skins[ndx];
  cairo_t *dst = skins[BASE].cairo;
  cairo_set_source_surface(dst, src->surface, src->rect->x, src->rect->y);
  cairo_rectangle(dst, src->rect->x, src->rect->y, src->rect->width, src->rect->height);
  cairo_fill(dst);
  return status(dst, __FUNCTION__);
}

static void paint(void) {
  paint_on_base(WORK);
  if (params->graph_type == GT_CURVE) paint_on_base(LAYER);
  paint_on_base(GRID);
  if (params->enable_legend) paint_on_base(LEGEND);
  backend_flush();
}

static bool set_pango(int ndx) {
  static char *font_family = "monospace";
  PangoFontDescription *font = pango_font_description_new();
  if (!font) {
    WARNX("Cannot allocate new pango font");
    return false;
  }
  pango_font_description_set_family(font, font_family);
  pango_font_description_set_absolute_size(font, font_size * PANGO_SCALE);
  PangoLayout *layout = pango_cairo_create_layout(skins[ndx].cairo);
  if (!layout) {
    WARNX("Cannot create pango layout");
    pango_font_description_free(font);
    return false;
  }
  pango_layout_set_font_description(layout, font);
  skins[ndx].font = font;
  skins[ndx].pango = layout;
  return true;
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

	x_mil = POS_ROUND((MIL * (double)params->period) / vp.width);
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
	LENVALMIL(x_mil);
	printf("x-point=%.*fms\n", _l, _v);
#endif
}

static void draw_grid(void) {
	cairo_t *cr = skins[GRID].cairo;
	PangoLayout *pl = skins[GRID].pango;

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
	char buf[16];
	cairo_set_source_rgb(cr, 0, 0, 0);
	double coef1 = (double)datamax / cell.x / MIL;
	for (int i = 0, a = vp.height; i <= cell.x; i++, a -= cell.height) {
		cairo_move_to(cr, 0, a);
		sprintf(buf, "%*.1f", TICKLABEL_LEN, coef1 * i);
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
	}

	// plus axis labels
	cr = skins[BASE].cairo;
	pl = skins[BASE].pango;

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
	cairo_t *cr = skins[TEMP].cairo;
	cairo_save(cr);
	cairo_set_source_rgb(cr, 1, 1, 1);
	cairo_paint(cr);

	double sy = (double)datamax_prev / datamax;
	cairo_matrix_t m;
	cairo_matrix_init(&m, 1, 0, 0, sy, 0, vp.height * (1 - sy));
	cairo_transform(cr, &m);
	cairo_set_source_surface(cr, skins[WORK].surface, 0, 0);
	cairo_paint(cr);
	cairo_restore(cr);
	swap(WORK, TEMP);
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

static void draw_line(cairo_t *c, int i, int x0, int y0, int x1, int y1) {
  set_source_rgb_func(c, i);
  cairo_move_to(c, x0, y0);
  cairo_line_to(c, x1, y1);
  cairo_stroke(c);
}

static void graph_dot(cairo_t *c) {
  cairo_save(c);
  cairo_set_line_cap(c, CAIRO_LINE_CAP_ROUND);
  cairo_set_line_width(c, DOT_SIZE);
  int x0 = x_point[0];
  for (int i = display_offset; i < hops; i++) {
    int y0 = y_point[0][i];
    if (y0)
      draw_dot(c, i, x0, y0);
  }
  cairo_restore(c);
}

static void graph_line(cairo_t *c) {
  int x0 = x_point[0];
  int x1 = x_point[1];
  for (int i = display_offset; i < hops; i++) {
    int y0 = y_point[0][i];
    int y1 = y_point[1][i];
    if (y0 && y1)
      draw_line(c, i, x0, y0, x1, y1);
    else if (y1) {
      cairo_save(c);
      cairo_set_line_cap(c, CAIRO_LINE_CAP_ROUND);
      cairo_set_line_width(c, DOT_SIZE);
      draw_dot(c, i, x1, y1);
      cairo_restore(c);
    }
  }
  int *t = y_point[1];
  y_point[1] = y_point[0];
  y_point[0] = t;
}

static double distance(int x0, int y0, int x1, int y1) {
  int dx1 = x1 - x0; int dy1 = y1 - y0;
  return sqrt(dx1 * dx1 + dy1 * dy1);
}

static int centripetal(double d1, double q1, double d2, double q2, int p0, int p1, int p2) {
  double b = (d1*p0 - d2*p1 + (2*d1 + 3*q1*q2 + d2)*p2) / (3*q1*(q1 + q2));
  return POS_ROUND(b);
}

static void graph_curve(cairo_t *c) {
	int x3 = x_point[0];
	int x2 = x_point[1];
	int x1 = x_point[2];
	int x0 = x_point[3];

	for (int i = display_offset; i < hops; i++) {
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

			set_source_rgb_func(c, i);
			cairo_move_to(c, x1, y1);
			cairo_curve_to(c, ax, ay, bx, by, x2, y2);
//			cairo_line_to(c, x3, y3);
			cairo_stroke(c);
		} else if (y1 && y2)
			draw_line(c, i, x1, y1, x2, y2);
		else if (y2) {
			cairo_save(c);
			cairo_set_line_cap(c, CAIRO_LINE_CAP_ROUND);
			cairo_set_line_width(c, DOT_SIZE);
			draw_dot(c, i, x2, y2);
			cairo_restore(c);
		}

		if (y2 && y3) {
			cairo_t *layer = skins[LAYER].cairo;
			set_source_rgb_func(layer, i);
			cairo_move_to(layer, 0, y2);
			cairo_line_to(layer, x3 - x2, y3);
			cairo_stroke(layer);
		}
	}

	int *t = y_point[3];
	y_point[3] = y_point[2];
	y_point[2] = y_point[1];
	y_point[1] = y_point[0];
	y_point[0] = t;
}

static void print_legend_desc(int x, int y, char *desc, int desc_max) {
	if (desc) {
		cairo_t *cr = skins[LEGEND].cairo;
		PangoLayout *pl = skins[LEGEND].pango;
/*
		char *txt;
		PangoAttrList *attrs;
		pango_parse_markup(s, -1, 0, &attrs, &txt, NULL, NULL);
		if (!txt)
			return;
		if (strlen(txt) > desc_max)
			txt[desc_max] = 0;
*/
		if (strlen(desc) > desc_max)
			desc[desc_max] = 0;
		pango_layout_set_width(pl, (legend.width - x) * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);
		pango_layout_set_text(pl, desc, -1);
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
	PangoLayout *pl = skins[LEGEND].pango;
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
  cairo_t *cr = skins[LEGEND].cairo;
  cairo_set_source_rgb(cr, 1, 1, 1);
  cairo_paint(cr);
}

inline void cr_print_legend_header(char *header) {
  print_legend_desc(coords.stat_x, 0, header, coords.stat_max);
}

inline void cr_print_legend_footer(char *footer) {
  print_legend_desc(0, coords.text_y, footer, coords.footer_max);
}

void cr_print_hop(int at) {
	if (at < display_offset)
		return;
	cairo_t *cr = skins[LEGEND].cairo;
	PangoLayout *pl = skins[LEGEND].pango;

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
	cairo_t *cr = skins[LEGEND].cairo;
	PangoLayout *pl = skins[LEGEND].pango;
	cairo_set_source_rgb(cr, (data < 0) ? 1 : 0, 0, 0);
	cairo_move_to(cr, coords.host_x, coords.text_y);
	pango_layout_set_text(pl, host ? host : "???", -1);
	pango_cairo_show_layout(cr, pl);
	if (stat) {
		pango_layout_set_width(pl, (legend.width - coords.stat_x) * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_RIGHT);
		cairo_set_source_rgb(cr, (data < 0) ? 1 : 0, 0, 0);
		cairo_move_to(cr, coords.stat_x, coords.text_y);
		if (strlen(stat) > coords.stat_max)
			stat[coords.stat_max] = 0;
		pango_layout_set_text(pl, stat, -1);
		pango_cairo_show_layout(cr, pl);
		pango_layout_set_width(pl, -1);
		pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
	}
	coords.text_y += coords.dy;
	coords.line_y += coords.dy;
}

static void rescale(long max) {
  datamax_prev = datamax;
  max += max * DATAMAX_EXTRA / 100;
  datamax = (max < DATAMAX_MIN) ? DATAMAX_MIN : max;
  draw_grid();
  scale_viewport();
  for (int i = 0; i < SPLINE_POINTS; i++)
    for (int j = 0; j < hops; j++)
      if (y_point[i][j])
        y_point[i][j] = vp.height - POS_ROUND(((double)(vp.height - y_point[i][j]) * datamax_prev) / datamax);
}

void cr_redraw(int *data) {
	static long viewport_datamax;
	static time_t viewport_period, remaining_time;
	if (!viewport_period)
		viewport_period = MIL * CYCLE_FACTOR * params->period + 0.5;
	bool f_repaint = false;

	// timing
	struct timespec now, tv;
	clock_gettime(CLOCK_MONOTONIC, &now);
	timespecsub(&now, &last, &tv);
	time_t dt = time2msec(tv);
	time_t unclosed_dt = dt + remaining_time;
	last = now;

	viewport_period -= dt;
	if (viewport_period < 0) {
		if (datamax > (viewport_datamax + DATAMAX_MIN))
			rescale(viewport_datamax);
		viewport_period = viewport_datamax = 0;
	}

	time_t dx = unclosed_dt / x_mil;
	remaining_time = unclosed_dt % x_mil;

	if (dx) {	// work
		// mean
		for (int i = 0; i < hops; i++)
			if (unclosed_data[i].count) {
				if (data[i] >= 0)
					data[i] = (data[i] + unclosed_data[i].data) / (unclosed_data[i].count + 1);
				else
					data[i] = unclosed_data[i].data / unclosed_data[i].count;
				unclosed_data[i].data = 0;
				unclosed_data[i].count = 0;
			}

		// max
		long _max = 0;
		for (int i = 0; i < hops; i++) {
			time_t d = data[i];
			if (d > _max)
				_max = d;
			y_point[0][i] = data_scale(d);
		}
		if (_max > viewport_datamax)
			viewport_datamax = _max;
		if (_max > datamax)
			rescale(_max);

		// shift
		if (dx < vp.width) {
			cairo_t *cr = skins[TEMP].cairo;
			cairo_set_source_surface(cr, skins[WORK].surface, -dx, 0);
			cairo_rectangle(cr, 0, 0, vp.width - dx, vp.height);
			cairo_fill(cr);
			swap(WORK, TEMP);
		} else
			dx = vp.width;

		// clearing
		time_t cl_dx = dx;
		if (params->graph_type == GT_CURVE) {
			vp_layer.width = x_point[0] - x_point[1];
			cl_dx += vp_layer.width;
			vp_layer.x = vp.x + vp.width - vp_layer.width;
			cairo_t *cr = skins[LAYER].cairo;
			cairo_set_source_rgb(cr, 1, 1, 1);
			cairo_paint(cr);
		}
		cairo_t *cr = skins[WORK].cairo;
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, vp.width - cl_dx, 0, cl_dx, vp.height);
		cairo_fill(cr);

		if (params->graph_type == GT_CURVE) {
			x_point[3] = x_point[2] - dx;
			x_point[2] = x_point[1] - dx;
			x_point[1] = x_point[0] - dx;
		} else if (params->graph_type == GT_LINE)
			x_point[1] = x_point[0] - dx;

		graph_func(cr);	// fill new area
		f_repaint = true;
	} else {	// accumulate
		for (int i = 0; i < hops; i++)
			if (data[i] >= 0) {
				unclosed_data[i].data += data[i];
				unclosed_data[i].count++;
			}
	}

	if (unclosed_dt > MIL) {  // top: systime
		cairo_t* cr = skins[BASE].cairo;
		PangoLayout *pl = skins[BASE].pango;
		pango_layout_set_width(pl, vp.width * PANGO_SCALE);
		pango_layout_set_alignment(pl, PANGO_ALIGN_CENTER);
		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, vp.x + coords.label_w, (vp.y - 3 * font_size / 2) / 2, vp.width - coords.label_w, 2 * font_size);
		cairo_fill(cr);
		cairo_set_source_rgb(cr, 0, 0, 0);
		cairo_move_to(cr, vp.x, (vp.y - font_size) / 2);
		char buf[256];
		time_t t = time(NULL);
		int l = snprintf(buf, sizeof(buf), "%s", ctime(&t));
		buf[--l] = 0; // '\n' from ctime
		if (iargs)
			mc_snprint_args(buf + l, sizeof(buf) - l);
		pango_layout_set_text(pl, buf, -1);
		pango_cairo_show_layout(cr, pl);
		pango_layout_set_alignment(pl, PANGO_ALIGN_LEFT);
		if (!f_repaint)
			f_repaint = true;
	}

	if ((dx && (unclosed_dt > MIL)) ||
		((tm_fmt == TM_MMSS) && (unclosed_dt > MIL)) ||
		((tm_fmt == TM_HHMM) && (unclosed_dt > 60 * MIL))) {	// bottom: x-axis tick marks

		cairo_t* cr = skins[BASE].cairo;
		PangoLayout *pl = skins[BASE].pango;

		cairo_set_source_rgb(cr, 1, 1, 1);
		cairo_rectangle(cr, vp.x - coords.label_w / 2, vp.y + vp.height, vp.width + coords.label_w, 3 * font_size);
		cairo_fill(cr);

		time_t actual_sec = now.tv_sec - POS_ROUND(wait_time * MIL) / MIL;
		if ((now.tv_nsec / MICRO) < (POS_ROUND(wait_time * MIL) % MIL))
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
		paint();
}

static void horizontal(cairo_t *c, double x, double w, cairo_surface_t *src, int dx) {
  cairo_save(c);
  src ? cairo_set_source_surface(c, src, dx, 0) : cairo_set_source_rgb(c, 1, 1, 1);
  cairo_rectangle(c, x, 0, w, vp.height);
  cairo_fill(c);
  cairo_restore(c);
}

void cr_net_reset(int paused) {
  if (!paused)
    horizontal(skins[WORK].cairo, 0, vp.width, NULL, 0);
  else {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if ((now.tv_sec - last.tv_sec) < params->period) { // more precisely
      struct timespec tv;
      timespecsub(&now, &last, &tv);
      int dx = time2msec(tv) / x_mil;
      horizontal(skins[TEMP].cairo, 0, vp.width - dx, skins[WORK].surface, -dx);
      swap(WORK, TEMP);
      horizontal(skins[WORK].cairo, vp.width - dx, dx, NULL, 0);
    }
  }
  paint();
  for (int i = 0; i < SPLINE_POINTS; i++)
    memset(y_point[i], 0, maxTTL * sizeof(int));
  memset(unclosed_data, 0, maxTTL * sizeof(unclosed_data_t));
}

static void destroy_skin(skin_t *s) {
  if (s->pango) {
    g_object_unref(s->pango);
    s->pango = NULL;
  }
  if (s->font) {
    pango_font_description_free(s->font);
    s->font = NULL;
  }
  if (s->cairo) {
    cairo_destroy(s->cairo);
    s->cairo = NULL;
  }
  if (s->surface) {
    cairo_surface_destroy(s->surface);
    s->surface = NULL;
  }
}

void cr_close(void) {
  if (unclosed_data)
    free(unclosed_data);
  for (int i = 0; i < SPLINE_POINTS; i++)
    if (y_point[i])
      free(y_point[i]);
  for (int i = 0; i < SKINS; i++) {
    if ((i == LEGEND) && !params->enable_legend) continue;
    if ((i == LAYER) && (params->graph_type != GT_CURVE)) continue;
    destroy_skin(&skins[i]);
  }
  backend_destroy_window();
// minimize memory-related complaints (libasan, valgrind)
  pango_cairo_font_map_set_default(NULL);
  cairo_debug_reset_static_data();
#ifdef FC_FINI
  FcFini();
#endif
}

static void cr_resize(int width, int height, int shift) {
	if (((!base_window.width) || (!base_window.height)) ||
		((base_window.width == width) && (base_window.height == height)))
		return;
	if (!skins[BASE].cairo)
		return;
	GCMSG_("%sresize: (%d, %d) => (%d, %d)\n", shift ? "shift+" : "", base_window.width, base_window.height, width, height);
	if (shift) {
		GCMSG_("legend: (%d, %d, %d, %d) => ", legend.x, legend.y, legend.width, legend.height);
		legend.width += width - base_window.width;
		if (legend.width < 0)
			legend.width = 0;

		legend.height += height - base_window.height;
		if (legend.height < 0)
			legend.height = 0;
		GCMSG_("(%d, %d, %d, %d)\n", legend.x, legend.y, legend.width, legend.height);
		base_window.width = width;
		base_window.height = height;
		return;
	}
	base_window.width = width;
	base_window.height = height;

	if (shift)
		return;

	set_viewport_params();
	if (!create_surfaces(1)) {
		WARNX("surface creation failed");
		return;
	}
	for (int i = 0; i < SKINS; i++) {
		if ((i == LEGEND) && !params->enable_legend)
			continue;
		pango_font_description_set_absolute_size(skins[i].font, font_size * PANGO_SCALE);
	}

	action = ACTION_RESIZE;

	// workarea rescaling
	cairo_t *cr = skins[WORK].cairo;
	cairo_save(cr);
	cairo_matrix_t m;
	cairo_matrix_init(&m, (double)vp.width / vp_prev.width, 0, 0,
		(double)vp.height / vp_prev.height, 0, 0);
	cairo_transform(cr, &m);
	cairo_set_source_surface(cr, skins[TEMP].surface, 0, 0);
	cairo_rectangle(cr, 0, 0, vp_prev.width, vp_prev.height);
	cairo_fill(cr);
	cairo_restore(cr);

	// spline point recalculation
	for (int i = 0; i < SPLINE_POINTS; i++) {
		double x = x_point[i];
		double y = 0;
		cairo_matrix_transform_point(&m, &x, &y);
		x_point[i] = POS_ROUND(x);
		for (int j = 0; j < hops; j++)
			if (y_point[i][j]) {
				x = 0;
				y = y_point[i][j];
				cairo_matrix_transform_point(&m, &x, &y);
				y_point[i][j] = POS_ROUND(y);
			}
	}
	x_point[0] = vp.width;

	if (!clone(BASE, TEMP, &vp))
		return;
	draw_grid();
	paint();
}

bool cr_open(cr_params_t *cr_params) {
	params = cr_params;
	GCMSG_("params: %s", "type=");
	switch (params->graph_type) {
		case GT_DOT:
			graph_func = graph_dot;
			GCMSG("dot");
			break;
		case GT_LINE:
			graph_func = graph_line;
			GCMSG("line");
			break;
		case GT_CURVE:
			graph_func = graph_curve;
			GCMSG("curve");
			break;
		default:
			params->graph_type = GT_CURVE;
			graph_func = graph_curve;
			GCMSG("curve");
	}

	if (params->period)
		params->period *= GRIDLINES;
	else
		params->period = VIEWPORT_PERIOD;
	GCMSG_(", period=%dsec", params->period);
	tm_fmt = (params->period < 3600) ? TM_MMSS : TM_HHMM;

	if (params->enable_legend)
		base_window.height *= 1.6;

	GCMSG_(", legend=%d, multipath=%d, jitter_graph=%d\n", params->enable_legend, params->enable_multipath, params->jitter_graph);
	set_source_rgb_func = (maxTTL < cr_colors_max) ? set_source_rgb_dir : set_source_rgb_mod;

	if (backend_create_window(&base_window, cr_resize)) {
		unclosed_data = calloc(maxTTL, sizeof(unclosed_data_t));
		if (!unclosed_data) {
			WARN_("calloc(%d, %zd)", maxTTL, sizeof(unclosed_data_t));
			return false;
		}
		for (int i = 0; i < SPLINE_POINTS; i++) {
			y_point[i] = calloc(maxTTL, sizeof(int));
			if (!y_point[i]) {
				WARN_("calloc(%d, %zd)", maxTTL, sizeof(int));
				return false;
			}
		}
		datamax = datamax_prev = DATAMAX_MIN;
		set_viewport_params();
	} else
		return false;
	if (!create_surfaces(0)) {
		WARNX("Surface creation failed");
		return false;
	}
	for (int i = 0; i < SKINS; i++) {
		if ((i == LEGEND) && !params->enable_legend)
			continue;
		if ((i == LAYER) && (params->graph_type != GT_CURVE))
			continue;
		if (!set_pango(i))
			return false;
	}
	draw_grid();
	paint();

	clock_gettime(CLOCK_MONOTONIC, &last);
	return true;
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

