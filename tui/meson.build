
# TUI part of mtr085-meson

lib = 'ncursesw'
libcurses = dependency(lib, required: false)
if not libcurses.found()
  libcurses = cc.find_library(lib, required: false)
  if not libcurses.found()
    lib = 'ncurses'
    libcurses = dependency(lib, required: false)
    if not libcurses.found()
      libcurses = cc.find_library(lib, required: false)
      if not libcurses.found()
        lib = 'curses'
        libcurses = dependency(lib, required: false)
        if not libcurses.found()
          libcurses = cc.find_library(lib)
        endif
      endif
    endif
  endif
endif

config.set_quoted('TUIKIND', lib)
deps += libcurses
fns = ['curses_version', 'use_default_colors']
if mouse
  fns += 'mousemask'
endif
foreach fn: fns
  if cc.has_function(fn, dependencies: libcurses)
    config.set('HAVE_' + fn.underscorify().to_upper(), 1)
  endif
endforeach

tuidirs = ['ncursesw', 'ncurses', '']
tuiprfx = ['n', '']
foreach dir: tuidirs
  foreach prfx: tuiprfx
    headers += dir / (prfx + 'curses.h')
  endforeach
endforeach

if menu
  lib = 'menu'
  libmenu = dependency(lib)
  if not libmenu.found()
    libmenu = cc.find_library(lib)
  endif
  foreach dir: tuidirs
    headers += dir / 'menu.h'
  endforeach
  fn = 'new_menu'
  if cc.has_function(fn, dependencies: libmenu)
    config.set('HAVE_' + fn.underscorify().to_upper(), 1)
    deps += libmenu
  endif
endif

if unicode
  fn = 'add_wch'
  assert(cc.has_function(fn, dependencies: libcurses), 'UNICODE is enabled, but no wchar library found')
endif

srcf += files('tui.c')
srcf += files('chart.c')
srcf += files('action.c')
optlist += '+TUI'
config.set('TUIMODE', 1)

if mouse and not config.has('HAVE_MOUSEMASK')
  mouse = false
endif
if mouse
  optlist += '+MOUSE'
  config.set('WITH_MOUSE', 1)
else
  optlist += '-MOUSE'
  manexcl += 'M'
endif

if menu and not config.has('HAVE_NEW_MENU')
  menu = false
endif
if menu
  optlist += '+MENU'
  config.set('WITH_MENU', 1)
else
  optlist += '-MENU'
endif

