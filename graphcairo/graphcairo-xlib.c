#include <stdio.h>
#include <stdlib.h>
#include <X11/Xlib.h>

#define XK_LATIN1
#define XK_MISCELLANY
#include <X11/keysymdef.h>

#include <cairo/cairo-xlib.h>
#include "graphcairo-backend.h"

static Display *display;
static Window window;
static int screen;
static Atom delete_window_atom;
static frontend_resize_t frontend_resize;
static int shiftkey_pressed;

cairo_surface_t* backend_create_surface(int width, int height) {
	return cairo_xlib_surface_create(display, window, DefaultVisual(display, screen), width, height);
}

int backend_create_window(cairo_rectangle_int_t *rectangle, frontend_resize_t frontend_resize_func) {
	frontend_resize = frontend_resize_func;
	display = XOpenDisplay(NULL);
	if (!display) {
		fprintf(stderr, "xlib backend_create_window(): can't open display\n");
		return 0;
	}
	screen = DefaultScreen(display);
	window = XCreateSimpleWindow(display, RootWindow(display, screen),
		rectangle->x, rectangle->y, rectangle->width, rectangle->height, 0,
		BlackPixel(display, screen), WhitePixel(display, screen));
	XSelectInput(display, window,
		ExposureMask | StructureNotifyMask | KeyPressMask | KeyReleaseMask);
	XMapWindow(display, window);
	delete_window_atom = XInternAtom(display, "WM_DELETE_WINDOW", False);
	XSetWMProtocols(display, window, &delete_window_atom, 1);
	XFlush(display);
	while (1) {
		XEvent ev;
		XNextEvent(display, &ev);
		if (ev.type == Expose)
			break;
	}
	return 1;
}

void backend_destroy_window(void) {
	XDestroyWindow(display, window);
	XCloseDisplay(display);
}

void backend_flush(void) {
	XFlush(display);
}

int keysym_to_char(KeySym keysym) {
	int c = 0;
	// [a-zA-Z\-\+ ]
	if ((keysym >= XK_a) && (keysym <= XK_z))
		c = (int)'a' + (keysym - XK_a);
	else if ((keysym >= XK_A) && (keysym <= XK_Z))
		c = (int)'A' + (keysym - XK_A);
	else if (keysym == XK_space)
		c = (int)' ';
	else if (keysym == XK_KP_Add)
		c = (int)'+';
	else if ((keysym == XK_minus) || (keysym == XK_KP_Subtract))
		c = (int)'-';
	return c;
}

int keycode_to_char(XKeyEvent *ev) {
	int keysyms_per_keycode_return;
	KeySym *p = XGetKeyboardMapping(display, ev->keycode, 2, &keysyms_per_keycode_return);
	KeySym keysym = 0;
	KeySym keymod = 0;
	if (p) {
		keysym = *p;
		keymod = *(p + 1);
	}
	XFree(p);

	if ((keysym == XK_Shift_L) || (keysym == XK_Shift_R) ||
		(keymod == XK_Shift_L) || (keymod == XK_Shift_R))
		shiftkey_pressed = (ev->type == KeyPress) ? 1 : 0;
#if 0
	printf("keysym=0x%x, keymod=0x%x, shiftkey=%d, type=%d\n",
		(unsigned int)keysym, (unsigned int)keymod, shiftkey_pressed, ev->type);
#endif

	int c = 0;
	if (ev->type == KeyRelease) {
		if ((keymod == XK_plus) && shiftkey_pressed)
			return '+';
		c = keysym_to_char(keysym);
	}
	return c;
}

int backend_dispatch_event(void) {
	int key = 0;
	XEvent event;
	XEvent *ev = &event;
	while (XPending(display)) {
		XNextEvent(display, ev);
		switch (event.type) {
			case ConfigureNotify:
				frontend_resize(((XConfigureEvent*)ev)->width,
					((XConfigureEvent*)ev)->height, shiftkey_pressed);
				break;
			case Expose:
				break;
			case ClientMessage:
			    if ((Atom)event.xclient.data.l[0] == delete_window_atom)
					key = 'q';
				break;
			case KeyPress:
			case KeyRelease:
				key = keycode_to_char((XKeyEvent*)ev);
				break;
			default:
//printf("got event: %d\n", ev->response_type & ~0x80);
				break;
		}
	}
	return key;
}

