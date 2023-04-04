#ifndef GRAPHCAIRO_BACKEND_H
#define GRAPHCAIRO_BACKEND_H

#include <cairo.h>

#if CAIRO_VERSION < CAIRO_VERSION_ENCODE(1, 10, 0)
typedef struct {
	int x, y;
	int width, height;
} cairo_rectangle_int_t;
#endif

typedef void (*frontend_resize_t)(int, int, int);
bool backend_create_window(cairo_rectangle_int_t *rectangle, frontend_resize_t frontend_resize_func);
void backend_destroy_window(void);
cairo_surface_t* backend_create_surface(int width, int height);
int backend_dispatch_event(void);
void backend_flush(void);

#endif
