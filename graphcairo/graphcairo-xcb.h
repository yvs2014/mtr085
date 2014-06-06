#ifndef GRAPHCAIRO_XCB_H
#define GRAPHCAIRO_XCB_H

#include <cairo.h>

typedef void (*frontend_resize_t)(int, int, int);
int backend_create_window(int width, int height,
	   	frontend_resize_t frontend_resize_func);
void backend_destroy_window(void);
cairo_surface_t* backend_create_surface(int width, int height);
int backend_dispatch_event(void);
void backend_flush(void);

#endif
