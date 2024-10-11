
#include <stdio.h>
#include <ctype.h>
#include <xcb/xcb.h>
#include <xcb/xcb_keysyms.h>
#define XK_LATIN1
#define XK_MISCELLANY
#include <X11/keysymdef.h>
#include <cairo/cairo-xcb.h>

#include "graphcairo-backend.h"
#include "common.h"

static xcb_connection_t *connection;
static xcb_window_t window;
static xcb_screen_t *screen;
static xcb_visualtype_t *visual_type;
static xcb_atom_t delete_window_atom;
static frontend_resize_t frontend_resize;
static int shiftkey_pressed;

static void root_visual_type(void) {
  for (xcb_depth_iterator_t i = xcb_screen_allowed_depths_iterator(screen); i.rem; xcb_depth_next(&i))
    for (xcb_visualtype_iterator_t j = xcb_depth_visuals_iterator(i.data); j.rem; xcb_visualtype_next(&j))
      if (screen->root_visual == j.data->visual_id) {
        visual_type = j.data;
        return;
      }
}

cairo_surface_t* backend_create_surface(int width, int height) {
	return cairo_xcb_surface_create(connection, window, visual_type, width, height);
}

static void set_delete_window_atom() {
	xcb_generic_error_t *error;
	xcb_intern_atom_cookie_t cookie = xcb_intern_atom(connection, 1, 12, "WM_PROTOCOLS");
	xcb_intern_atom_reply_t* reply = xcb_intern_atom_reply(connection, cookie, &error);
	if (!reply) {
		WARNX("WM_PROTOCOLS error %d", error->error_code);
		free(error);
		return;
	}
	xcb_intern_atom_cookie_t cookie2 = xcb_intern_atom(connection, 0, 16, "WM_DELETE_WINDOW");
	xcb_intern_atom_reply_t* reply2 = xcb_intern_atom_reply(connection, cookie2, &error);
	if (reply2) {
		xcb_change_property(connection, XCB_PROP_MODE_REPLACE, window, (*reply).atom, 4, 32, 1, &(*reply2).atom);
		delete_window_atom = (*reply2).atom;
		free(reply2);
	} else {
		WARNX("WM_DELETE_WINDOW error %d", error->error_code);
		free(error);
	}
	free(reply);
}

#define DISCONN_AND_RETURN(msg) { \
	WARNX("%s: error code %d", msg, error->error_code); \
	free(error); \
	xcb_destroy_window(connection, window); \
	xcb_disconnect(connection); \
	return false; \
}

bool backend_create_window(cairo_rectangle_int_t *rectangle, frontend_resize_t frontend_resize_func) {
	frontend_resize = frontend_resize_func;

	int screen_no;
	connection = xcb_connect(NULL, &screen_no);
	if (xcb_connection_has_error(connection)) {
		WARNX("Cannot connect to X server");
		return false;
	}

	const xcb_setup_t *setup = xcb_get_setup(connection);
	screen = NULL;
	for (xcb_screen_iterator_t i = xcb_setup_roots_iterator(setup); i.rem; --screen_no, xcb_screen_next(&i)) {
		if (screen_no == 0) {
			screen = i.data;
			break;
		}
	}
	if (!screen) {
		WARNX("No screen found");
		xcb_disconnect(connection);
		return false;
	}

	window = xcb_generate_id(connection);
	uint32_t mask = XCB_CW_BACK_PIXEL | XCB_CW_EVENT_MASK;
	uint32_t values[2];
	values[0] = screen->white_pixel;
	values[1] = XCB_EVENT_MASK_EXPOSURE | XCB_EVENT_MASK_STRUCTURE_NOTIFY | XCB_EVENT_MASK_KEY_PRESS | XCB_EVENT_MASK_KEY_RELEASE;
	xcb_void_cookie_t cookie;
	xcb_generic_error_t *error;

	cookie = xcb_create_window_checked(connection, XCB_COPY_FROM_PARENT,
		window, screen->root, rectangle->x, rectangle->y, rectangle->width, rectangle->height, 0,
		XCB_WINDOW_CLASS_INPUT_OUTPUT, screen->root_visual, mask, values);
	error = xcb_request_check(connection, cookie);
	if (error)
		DISCONN_AND_RETURN("Cannot create window");

	cookie = xcb_map_window_checked(connection, window);
	error = xcb_request_check(connection, cookie);
	if (error)
		DISCONN_AND_RETURN("Cannot map window");

	set_delete_window_atom();

	xcb_flush(connection);
	if (xcb_connection_has_error(connection)) {
		WARNX("Connection has errors");
		return false;
	}

	while (1) {
		xcb_generic_event_t *ev = xcb_wait_for_event(connection);
		if (!ev) {
			WARNX("Event wait failed");
			return false;
		}
		uint8_t type = ev->response_type;
		free(ev);
		if ((type & ~0x80) == XCB_EXPOSE) {
			root_visual_type();
			break;
		}
	}

	return true;
}

void backend_destroy_window(void) {
	xcb_destroy_window(connection, window);
	xcb_disconnect(connection);
}

void backend_flush(void) {
	xcb_flush(connection);
}

static int keysym_to_char(xcb_keysym_t keysym) {
	int c = 0;
	// [a-zA-Z\-\+ ]
	if ((keysym >= XK_a) && (keysym <= XK_z)) {
		c = (int)'a' + (keysym - XK_a);
		if (shiftkey_pressed)
			c = toupper(c);
	} else if ((keysym >= XK_A) && (keysym <= XK_Z)) {
		c = (int)'A' + (keysym - XK_A);
		if (shiftkey_pressed)
			c = tolower(c);
	} else if (keysym == XK_space)
		c = (int)' ';
	else if ((keysym == XK_plus) || (keysym == XK_KP_Add))
		c = (int)'+';
	else if ((keysym == XK_minus) || (keysym == XK_KP_Subtract))
		c = (int)'-';
	return c;
}

static int keycode_to_char(xcb_key_release_event_t *ev) {
	xcb_key_symbols_t *key_symbols = xcb_key_symbols_alloc(connection);
	if (!key_symbols)
		return 0;

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
	xcb_key_symbols_free(key_symbols);
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

