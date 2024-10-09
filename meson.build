project('mtr085', 'c',
  default_options: [ # 'c_std=gnu99,c99'
    'warning_level=1'],
  meson_version: '>= 0.49',
  license: 'GPL-2.0-or-later',
  version: '.'.join(['0', '85', find_program('git', required: false).found() ?
    run_command('git', 'rev-list', '--count', '97af563..HEAD', check: false).stdout().strip() : ''
  ]).strip('.'),
)
#add_project_arguments('-fanalyzer', language: 'c') # gcc static analysis

name = 'mtr'
config = configuration_data()
config.set_quoted('PACKAGE_NAME', name)
version = meson.project_version().split('.')
if version.length() > 2
  config.set_quoted('GITREV', version[2])
  version = [version[0], version[1]]
endif
config.set_quoted('VERSION', '.'.join(version))

# options
optlist = []
cap        = get_option('CAP')
curses     = get_option('CURSES')
unicode    = get_option('UNICODE')
dns        = get_option('DNS')
idn        = get_option('IDN')
ipinfo     = get_option('IPINFO')
split      = get_option('SPLIT')
graph      = get_option('GRAPH')
ipv6       = get_option('IPV6')
mpls       = get_option('MPLS')
outfmt = []
outraw     = get_option('OUTRAW')
outtxt     = get_option('OUTTXT')
outcsv     = get_option('OUTCSV')
outjson    = get_option('OUTJSON')
outxml     = get_option('OUTXML')
deblog = []
debpoll   = get_option('DEBPOLL')
debnet    = get_option('DEBNET')
debdns    = get_option('DEBDNS')
debipinfo = get_option('DEBIPINFO')
sbin      = get_option('SBIN')
manexcl = []

if meson.version().version_compare('>=0.53')
  summary({'CAP': cap,
    'CURSES': curses, 'UNICODE': unicode,
    'DNS': dns, 'IDN': idn, 'IPINFO': ipinfo,
    'SPLIT': split, 'GRAPH': graph,
    'IPV6': ipv6, 'MPLS': mpls,
  }, bool_yn: true)
endif
headers = ['sys/param.h', 'netdb.h']
incdir  = []

# sources
srcn  = [name]
srcn += 'net'
srcn += 'display'
srcn += 'report'
srcn += 'poll'
srcn += 'aux'

# deps and checkouts
cc   = meson.get_compiler('c')
deps = []
cpps = []

# optional: CAP (default yes)
if cap
  lib = 'cap'
  libcap = dependency('lib' + lib, required: false)
  if not libcap.found()
    libcap = cc.find_library('cap')
  endif
  deps += libcap
  config.set('LIBCAP', 1)
  optlist += '+CAP'
else
  optlist += '-CAP'
endif
#
if curses
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
  deps += libcurses
  fn = 'use_default_colors'
  if cc.has_function(fn, dependencies: libcurses)
    config.set('HAVE_' + fn.underscorify().to_upper(), 1)
  endif
  headers += 'ncursesw/ncurses.h'
  headers += 'ncursesw/curses.h'
  headers += 'ncurses/ncurses.h'
  headers += 'ncurses/curses.h'
  headers += 'ncurses.h'
  headers += 'curses.h'
  if unicode
    fn = 'add_wch'
    assert(cc.has_function(fn, dependencies: libcurses), 'UNICODE is enabled, but no wchar library found')
  endif
  srcn += 'curses'
  optlist += '+CURSES'
  config.set('CURSESMODE', 1)
else
  optlist += '-CURSES'
endif
#
if unicode
  headers += 'wchar.h'
  headers += 'wctype.h'
  headers += 'locale.h'
  headers += 'langinfo.h'
  optlist += '+UNICODE'
  config.set('WITH_UNICODE', 1)
else
  optlist += '-UNICODE'
endif
#
if dns
  fn = 'res_mkquery'
  incl  = '#include <netinet/in.h>\n'
  incl += '#include <resolv.h>\n'
  res = 'resolv'
  libres = cc.find_library(res, required: false)
  if cc.has_function(fn, prefix: incl, dependencies: libres)
    deps += libres
  else
    if not cc.has_function(fn, prefix: incl)
      res = 'network'
      libres = cc.find_library(res, required: false)
      assert(cc.has_function(fn, prefix: incl, dependencies: libres), 'DNS is enabled, but resolv not detected')
      deps += libres
    endif
  endif
  fn = 'res_nmkquery'
  if cc.has_function(fn, prefix: incl, dependencies: libres)
    config.set('HAVE_' + fn.underscorify().to_upper(), 1)
  endif
  fn = 'gethostbyaddr'
  incl += '\n#include <netdb.h>'
  if not cc.has_function(fn, prefix: incl, dependencies: libres)
    libnsl = cc.find_library('nsl')
    assert(cc.has_function(fn, prefix: incl, dependencies: libnsl), 'DNS is enabled, but NSL not found')
    deps += libnsl
  endif
  headers += 'arpa/nameser.h'
  headers += 'sys/types.h'
  srcn += 'dns'
  optlist += '+DNS'
  config.set('ENABLE_DNS', 1)
else
  optlist += '-DNS'
  manexcl += 'n'
  manexcl += 'N'
endif
#
if idn
  lib = 'idn2'
  idn_dep = dependency('lib' + lib, required: false)
  if idn_dep.found()
    deps += idn_dep
  else
    libidn = cc.find_library(lib, required: false)
    if libidn.found()
      headers += lib / lib + '.h'
      deps += libidn
    else
      lib = 'idn'
      idn_dep = dependency('lib' + lib, required: false)
      if idn_dep.found()
        deps += idn_dep
      else
        libidn = cc.find_library(lib)
        deps += libidn
      endif
    endif
  endif
  config.set('LIB' + lib.to_upper(), 1)
  optlist += '+IDN'
else
  optlist += '-IDN'
endif
#
if ipinfo
  srcn += 'ipinfo'
  optlist += '+IPINFO'
  config.set('WITH_IPINFO', 1)
else
  optlist += '-IPINFO'
  manexcl += 'y'
endif
#
if split
  srcn += 'split'
  optlist += '+SPLIT'
  config.set('SPLITMODE', 1)
else
  optlist += '-SPLIT'
  manexcl += 'p'
endif
#
if graph
  grname = 'graphcairo'
  grbase = grname / grname
  add_global_arguments('-I' + meson.current_source_dir() / grname, language: 'c')
  deps += dependency('cairo')
  deps += dependency('pango')
  deps += dependency('pangocairo')
  lib = 'xcb'
  libx = cc.find_library(lib, required: false)
  if libx.found()
    ksym = 'xcb-keysyms'
    libksym = cc.find_library(ksym)
    deps += libksym
  else
    lib = 'x11'
    libx = cc.find_library(lib)
  endif
  deps += libx
  srcn += grbase
  srcn += '-'.join(grbase, name)
  srcn += '-'.join(grbase, lib)
  lib = 'fontconfig'
  libfc = cc.find_library(lib, required: false)
  if libfc.found() and cc.has_function('FcFini', dependencies: libfc)
    deps += libfc
    config.set('FC_FINI', 1)
  endif
  optlist += '+GRAPH'
  config.set('GRAPHMODE', 1)
else
  optlist += '-GRAPH'
  manexcl += 'g'
endif
#
if ipv6
  optlist += '+IPV6'
  config.set('ENABLE_IPV6', 1)
else
  optlist += '-IPV6'
  manexcl += '4'
  manexcl += '6'
endif
#
if mpls
  optlist += '+MPLS'
  config.set('WITH_MPLS', 1)
else
  optlist += '-MPLS'
  manexcl += 'e'
endif
#
# out format options
if outraw
  outfmt += 'raw'
  config.set('OUTPUT_FORMAT_RAW', 1)
else
  manexcl += 'or'
endif
if outtxt
  outfmt += 'text'
  config.set('OUTPUT_FORMAT_TXT', 1)
else
  manexcl += 'ot'
endif
if outcsv
  outfmt += 'csv'
  config.set('OUTPUT_FORMAT_CSV', 1)
else
  manexcl += 'oc'
endif
if outjson
  outfmt += 'json'
  config.set('OUTPUT_FORMAT_JSON', 1)
else
  manexcl += 'oj'
endif
if outxml
  outfmt += 'xml'
  config.set('OUTPUT_FORMAT_XML', 1)
else
  manexcl += 'ox'
endif
if outfmt.length() > 0
  optlist += 'OUTFMT=' + ','.join(outfmt)
else
  optlist += '-OUTFMT'
  manexcl += 'o'
endif
#
# syslog debug options
if debpoll
  deblog += 'poll'
  config.set('LOG_POLL', 1)
endif
if debnet
  deblog += 'net'
  config.set('LOG_NET', 1)
endif
if debdns
  deblog += 'dns'
  config.set('LOG_DNS', 1)
endif
if debipinfo
  deblog += 'ipinfo'
  config.set('LOG_IPINFO', 1)
endif
if deblog.length() > 0
  optlist += 'DEBLOG=' + ','.join(deblog)
else
  optlist += '-DEBLOG'
endif
#
config.set_quoted('BUILD_OPTIONS', ' '.join(optlist))
# end of options


# aux
srcs = []
foreach c: srcn
  srcs += c + '.c'
endforeach
#
foreach h: headers
  if cc.has_header(h)
    config.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach
#
fndesc = {
  'pow': {'libs': ['m'], 'hdr': 'math.h'},
  'warnx': {'libs': ['bsd'], 'hdr': 'err.h'},
  'socket': {'libs': ['socket', 'network'], 'hdr': 'sys/socket.h'},
  'strlcpy': {'libs': ['bsd'], 'hdr': 'bsd/stdlib.h', 'libhdr': true, 'req': false},
  'arc4random_uniform': {'libs': ['bsd'], 'hdr': 'bsd/stdlib.h', 'libhdr': true, 'req': false},
}
#
foreach fn, desc: fndesc
  libs   = desc['libs']
  hdr    = 'hdr' in desc ? desc['hdr'] : ''
  incl   = hdr == '' ? '' : '#include <' + hdr + '>'
  req    = 'req' in desc ? desc['req'] : true
  libhdr = 'libhdr' in desc ? desc['libhdr'] : false
  found = true
  if cc.has_function(fn, prefix: libhdr ? '' : incl)
    if not libhdr
      config.set('HAVE_' + hdr.underscorify().to_upper(), 1)
    endif
  else
    found = false
    foreach l: libs
      lib = dependency('lib' + l, required: false)
      if not lib.found()
        lib = cc.find_library(l, required: false)
      endif
      if lib.found() and cc.has_function(fn, prefix: incl, dependencies: lib)
        if libhdr
          config.set('HAVE_' + hdr.underscorify().to_upper(), 1)
        endif
        deps += lib
        found = true
        break
      endif
    endforeach
  endif
  if req
    assert(found, 'No @0@() found'.format(fn))
  endif
  if found
    config.set('HAVE_' + fn.underscorify().to_upper(), 1)
  endif
endforeach
#

# fin
#
config_h = 'config.h'
configure_file(input: config_h + '.meson', output: config_h, configuration: config)
if sbin
  executable(name, srcs, dependencies: deps, c_args: cpps, install: true,
    install_dir: get_option('prefix') / get_option('sbindir'))
else
  executable(name, srcs, dependencies: deps, c_args: cpps, install: true)
endif
#
man = name + '.8'
configure_file(input: man + '.in', output: man, copy: true)
manre = meson.current_build_dir() / man
if manexcl.length() > 0
  sed = find_program('sed', required : false)
  if sed.found()
    foreach opt: manexcl
      cmd = run_command(sed, '-i.bak', 's/^\(\.ds o' + opt + ' "\).*/\\1/', manre, check: false)
      if cmd.returncode() != 0
        warning(cmd.stderr())
      endif
    endforeach
  endif
endif
#
install_man(manre)

