
#include <stdio.h>
#include <ctype.h>
#include <X11/Xlib.h>
#define XK_LATIN1
#define XK_MISCELLANY
#include <X11/keysymdef.h>
#include <cairo/cairo-xlib.h>

#include "graphcairo-backend.h"
#include "common.h"

static Display *display;
static Window window;
static int screen;
static Atom delete_window_atom;
static frontend_resize_t frontend_resize;
static int shiftkey_pressed;

cairo_surface_t* backend_create_surface(int width, int height) {
  return cairo_xlib_surface_create(display, window, DefaultVisual(display, screen), width, height);
}

bool backend_create_window(cairo_rectangle_int_t *rectangle, frontend_resize_t frontend_resize_func) {
  frontend_resize = frontend_resize_func;
  display = XOpenDisplay(NULL);
  if (!display) {
    WARNX("Cannot open display");
    return false;
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
    XEvent event;
    XNextEvent(display, &event);
    if (event.type == Expose) break;
  }
  return true;
}

void backend_destroy_window(void) {
  XDestroyWindow(display, window);
  XCloseDisplay(display);
}

inline void backend_flush(void) { XFlush(display); }

static int keysym_to_char(KeySym keysym) {
  int ch = 0;
  // [a-zA-Z\-\+ ]
  if ((keysym >= XK_a) && (keysym <= XK_z)) {
    ch = 'a' + (keysym - XK_a);
    if (shiftkey_pressed) ch = toupper(ch);
  } else if ((keysym >= XK_A) && (keysym <= XK_Z)) {
    ch = 'A' + (keysym - XK_A);
    if (shiftkey_pressed) ch = tolower(ch);
  } else if (keysym == XK_space) {
    ch = ' ';
  } else if (keysym == XK_KP_Add) {
    ch = '+';
  } else if ((keysym == XK_minus) || (keysym == XK_KP_Subtract)) {
    ch = '-';
  }
  return ch;
}

static int keycode_to_char(XKeyEvent *event) {
  int keysyms_per_keycode_return = 0;
  KeySym *symmod = XGetKeyboardMapping(display, event->keycode, 2, &keysyms_per_keycode_return);
  KeySym keysym = symmod ? *symmod : 0;
  KeySym keymod = symmod ? *(symmod + 1) : 0;
  if (symmod) XFree(symmod);
  if ((keysym == XK_Shift_L) || (keysym == XK_Shift_R) ||
      (keymod == XK_Shift_L) || (keymod == XK_Shift_R))
    shiftkey_pressed = (event->type == KeyPress) ? 1 : 0;
  int ch = 0;
  if (event->type == KeyRelease)
    ch = ((keymod == XK_plus) && shiftkey_pressed) ? '+' : keysym_to_char(keysym);
  return ch;
}

int backend_dispatch_event(void) {
  int key = 0;
  while (XPending(display)) {
    XEvent event = {0};
    XNextEvent(display, &event);
    switch (event.type) {
      case ConfigureNotify:
        frontend_resize(
          ((XConfigureEvent*)&event)->width,
          ((XConfigureEvent*)&event)->height,
          shiftkey_pressed);
        break;
      case ClientMessage:
        if ((Atom)event.xclient.data.l[0] == delete_window_atom) key = 'q';
        break;
      case KeyPress:
      case KeyRelease:
        key = keycode_to_char((XKeyEvent*)&event);
        break;
      default: break;
    }
  }
  return key;
}

