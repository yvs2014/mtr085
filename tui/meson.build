
# TUI part of mtr085-meson

_lib = 'curses'
_prfx = ['n', '']
_sfx  = ['w', '']
tuisfx = ''
libtui = dependency('', required: false)
foreach _p: _prfx
  foreach _s: _sfx
    tuisfx = _s
    _l = _p + _lib + _s
    libtui = dependency(_l, required: false)
    if not libtui.found()
      libtui = cc.find_library(_l, required: false)
    endif
    if libtui.found()
      break
    endif
  endforeach
  if libtui.found()
    break
  endif
endforeach

assert(libtui.found(), 'no TUI(' + _lib + ') library found')
config.set_quoted('TUIKIND', _l)
deps += libtui

# detect wide-character support
_fn = 'add_wch'
_wide = cc.has_function(_fn, dependencies: libtui)
if unicode
  assert(_wide, 'UNICODE is enabled, but no wchar TUI found')
endif
if _wide
  config.set('TUIWIDE', 1)
endif

_dirs  = _wide ? ['ncursesw'] : []
_dirs += ['ncurses', '']
_prfx  = ['n', '']
foreach _d: _dirs
  foreach _p: _prfx
    headers += _d / (_p + 'curses.h')
  endforeach
endforeach

if menu
  _name = ['menu', 'form', 'panel']
  foreach _n: _name
    _lib = _n  + tuisfx
    _dep = dependency(_lib)
    if not _dep.found()
      _dep = cc.find_library(_lib)
    endif
    assert(_dep.found(), 'no ' + (_wide ? 'wide ' : '') + _lib + ' library found')
    deps += _dep
    foreach _d: _dirs
      headers += _d / _n + '.h'
    endforeach
  endforeach
endif

_fns = ['curses_version', 'use_default_colors']
if mouse
  _fns += 'mousemask'
endif
foreach _f: _fns
  if cc.has_function(_f, dependencies: libtui)
    config.set('HAVE_' + _f.underscorify().to_upper(), 1)
  endif
endforeach

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

if menu
  optlist += '+MENU'
  config.set('WITH_MENU', 1)
  srcf += files('kit.c')
else
  optlist += '-MENU'
endif

