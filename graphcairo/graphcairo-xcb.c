#include <stdio.h>
#include <stdlib.h>
#include <xcb/xcb.h>
#include <xcb/xcb_keysyms.h>

#define XK_LATIN1
#define XK_MISCELLANY
#include <X11/keysymdef.h>

#include <cairo/cairo-xcb.h>
#include "graphcairo-backend.h"

static xcb_connection_t *connection;
static xcb_window_t window;
static xcb_screen_t *screen;
static xcb_visualtype_t *visual_type;
static xcb_atom_t delete_window_atom;
static frontend_resize_t frontend_resize;
static int shiftkey_pressed;

void root_visual_type(void) {
    xcb_depth_iterator_t depth_iter;
    for (depth_iter = xcb_screen_allowed_depths_iterator(screen);
		depth_iter.rem; xcb_depth_next(&depth_iter)) {
			xcb_visualtype_iterator_t visual_iter;
			for (visual_iter = xcb_depth_visuals_iterator(depth_iter.data);
				visual_iter.rem; xcb_visualtype_next(&visual_iter))
				if (screen->root_visual == visual_iter.data->visual_id) {
					visual_type = visual_iter.data;
					return;
				}
	}
	visual_type = NULL;
}

cairo_surface_t* backend_create_surface(int width, int height) {
	return cairo_xcb_surface_create(connection, window, visual_type, width, height);
}

int backend_create_window(cairo_rectangle_int_t *rectangle, frontend_resize_t frontend_resize_func) {
	frontend_resize = frontend_resize_func;

	int screen_no;
	connection = xcb_connect(NULL, &screen_no);
	if (xcb_connection_has_error(connection)) {
		fprintf(stderr, "xcb backend_create_window(): can't connect to an X server\n");
		return 0;
	}

	const xcb_setup_t *setup = xcb_get_setup(connection);
	screen = NULL;
	xcb_screen_iterator_t screen_iter;
	for (screen_iter = xcb_setup_roots_iterator(setup); screen_iter.rem != 0;
		--screen_no, xcb_screen_next(&screen_iter))
		if (screen_no == 0) {
			screen = screen_iter.data;
			break;
		}

	window = xcb_generate_id(connection);
	uint32_t mask = XCB_CW_BACK_PIXEL | XCB_CW_EVENT_MASK;
	uint32_t values[2];
	values[0] = screen->white_pixel;
	values[1] = XCB_EVENT_MASK_EXPOSURE | XCB_EVENT_MASK_STRUCTURE_NOTIFY | XCB_EVENT_MASK_KEY_PRESS | XCB_EVENT_MASK_KEY_RELEASE;

	xcb_void_cookie_t cookie_window = xcb_create_window_checked(connection, XCB_COPY_FROM_PARENT,
		window, screen->root, rectangle->x, rectangle->y, rectangle->width, rectangle->height, 0,
	   	XCB_WINDOW_CLASS_INPUT_OUTPUT, screen->root_visual, mask, values);
	xcb_void_cookie_t cookie_map = xcb_map_window_checked(connection, window);

	xcb_generic_error_t *error = xcb_request_check(connection, cookie_window);
	if (error) {
		fprintf(stderr, "xcb backend_create_window(): can't create window : %d\n", error->error_code);
		xcb_destroy_window(connection, window);
		xcb_disconnect(connection);
		return 0;
	}
	error = xcb_request_check(connection, cookie_map);
	if (error) {
		fprintf(stderr, "xcb backend_create_window(): can't map window : %d\n", error->error_code);
		xcb_destroy_window(connection, window);
		xcb_disconnect(connection);
		return 0;
	}

	xcb_intern_atom_cookie_t cookie = xcb_intern_atom(connection, 1, 12, "WM_PROTOCOLS");
	xcb_intern_atom_reply_t* reply = xcb_intern_atom_reply(connection, cookie, 0);
	xcb_intern_atom_cookie_t cookie2 = xcb_intern_atom(connection, 0, 16, "WM_DELETE_WINDOW");
	xcb_intern_atom_reply_t* reply2 = xcb_intern_atom_reply(connection, cookie2, 0);
	xcb_change_property(connection, XCB_PROP_MODE_REPLACE, window, (*reply).atom, 4, 32, 1, &(*reply2).atom);
	delete_window_atom = (*reply2).atom;

	xcb_flush(connection);
	if (xcb_connection_has_error(connection)) {
		fprintf(stderr, "xcb backend_create_window() failed: xcb_connection_has_error()\n");
		return 0;
	}

	while (1) {
		xcb_generic_event_t *ev = xcb_wait_for_event(connection);
		if ((ev->response_type & ~0x80) == XCB_EXPOSE) {
			root_visual_type();
			break;
		}
	}

	return 1;
}

void backend_destroy_window(void) {
	xcb_destroy_window(connection, window);
	xcb_disconnect(connection);
}

void backend_flush(void) {
	xcb_flush(connection);
}

int keysym_to_char(xcb_keysym_t keysym) {
	int c = 0;
	// [a-zA-Z\-\+ ]
	if ((keysym >= XK_a) && (keysym <= XK_z))
		c = (int)'a' + (keysym - XK_a);
	else if ((keysym >= XK_A) && (keysym <= XK_Z))
		c = (int)'A' + (keysym - XK_A);
	else if (keysym == XK_space)
		c = (int)' ';
	else if ((keysym == XK_plus) || (keysym == XK_KP_Add))
		c = (int)'+';
	else if ((keysym == XK_minus) || (keysym == XK_KP_Subtract))
		c = (int)'-';
	return c;
}

int keycode_to_char(xcb_key_release_event_t *ev) {
	static xcb_key_symbols_t *key_symbols;
	if (!key_symbols)
		key_symbols = xcb_key_symbols_alloc(connection);

	xcb_keysym_t keysym = xcb_key_symbols_get_keysym(key_symbols, ev->detail, 0);
	xcb_keysym_t keymod = xcb_key_symbols_get_keysym(key_symbols, ev->detail, ev->state & XCB_MOD_MASK_SHIFT);

	int typ = ev->response_type & ~0x80;
	if ((keysym == XK_Shift_L) || (keysym == XK_Shift_R) ||
		(keymod == XK_Shift_L) || (keymod == XK_Shift_R))
		shiftkey_pressed = (typ == XCB_KEY_PRESS) ? 1 : 0;
#if 0
	printf("keysym=0x%x, keymod=0x%x, shiftkey=%d, type=%d\n",
		(unsigned int)keysym, (unsigned int)keymod, shiftkey_pressed, typ);
#endif

	int c = 0;
	if (typ == XCB_KEY_RELEASE)
		if (!(c = keysym_to_char(keysym)))
			c = keysym_to_char(keymod);
	return c;
}

int backend_dispatch_event(void) {
	int key = 0;
	xcb_generic_event_t *ev;
	while ((ev = xcb_poll_for_event(connection))) {
		switch (ev->response_type & ~0x80) {
			case XCB_CONFIGURE_NOTIFY:
				frontend_resize(((xcb_configure_notify_event_t*)ev)->width,
					((xcb_configure_notify_event_t*)ev)->height, shiftkey_pressed);
				break;
			case XCB_EXPOSE:
				break;
			case XCB_CLIENT_MESSAGE:
			    if ((*(xcb_client_message_event_t*)ev).data.data32[0] == delete_window_atom)
					key = 'q';
				break;
			case XCB_KEY_PRESS:
			case XCB_KEY_RELEASE:
				key = keycode_to_char((xcb_key_release_event_t *)ev);
				break;
			default:
//printf("got event: %d\n", ev->response_type & ~0x80);
				break;
		}
		free(ev);
	}
	return key;
}

