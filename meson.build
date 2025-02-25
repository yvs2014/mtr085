project('mtr085', 'c',
  default_options: [
#    'c_std=gnu99,c99',
#    'b_sanitize=address,undefined',
    'warning_level=3' ],
  meson_version: '>= 0.49',
  license: 'GPL-2.0-or-later',
  version: '.'.join(['0', '85', find_program('git', required: false).found() ?
    run_command('git', 'rev-list', '--count', '97af563..HEAD', check: false).stdout().strip() : ''
  ]).strip('.'),
)

name = 'mtr'
config = configuration_data()
config.set_quoted('PACKAGE_NAME', meson.project_name())
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
nls        = get_option('NLS')
dns        = get_option('DNS')
ipinfo     = get_option('IPINFO')
split      = get_option('SPLIT')
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

os   = host_machine.system()
cc   = meson.get_compiler('c')
deps = []
cpps = []
incdir  = []
headers = ['netdb.h', 'netinet/in.h', 'sys/param.h']
#

# sources
srcn  = [name]
srcn += 'net'
srcn += 'display'
srcn += 'report'
srcn += 'poll'
srcn += 'aux'

# probes
fndesc = {
  'pow': {'libs': ['m'], 'hdr': 'math.h'},
  'warnx': {'libs': [], 'hdr': 'err.h'},
  'socket': {'libs': ['socket', 'network'], 'hdr': 'sys/socket.h'},
  'strlcpy': {'libs': [], 'hdr': 'stdlib.h', 'libhdr': true, 'req': false},
  'arc4random_uniform': {'libs': [], 'hdr': 'stdlib.h', 'libhdr': true, 'req': false},
  'quick_exit':  {'libs': [], 'hdr': 'stdlib.h', 'req': false},
  'strerror_r':  {'libs': [], 'hdr': 'string.h', 'req': false},
  'localtime_r': {'libs': [], 'hdr': 'time.h',   'req': false},
  'uselocale':   {'libs': [], 'hdr': 'locale.h', 'req': false},
}

# optional: CAP (default yes)
if cap
  lib = 'cap'
  libcap = dependency('lib' + lib, required: false)
  if not libcap.found()
    libcap = cc.find_library(lib)
  endif
  deps += libcap
  config.set('LIBCAP', 1)
  optlist += '+CAP'
else
  optlist += '-CAP'
endif
#
if curses
#  lib = 'tinfo'
#  libtinfo = dependency('lib' + lib, required: false)
#  if not libtinfo.found()
#    libtinfo = cc.find_library(lib)
#  endif
#  deps += libtinfo
  #
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
if nls
  config.set('USE_NLS', 1)
  config.set_quoted('LOCALEDIR', join_paths(get_option('prefix'), get_option('localedir')))
  if os == 'freebsd' or os == 'openbsd'
    deps += cc.find_library('intl', has_headers: ['libintl.h'],
      dirs: ['/usr/local/lib'], header_args: ['-isystem/usr/local/include'])
  else
    fndesc += {'gettext': {'libs': ['intl'], 'hdr': 'libintl.h', 'req': true}}
  endif
  subdir('po')
  optlist += '+NLS'
else
  optlist += '-NLS'
endif
#
if dns
  fn = 'res_mkquery'
  hdrs = ['netinet/in.h', 'resolv.h', 'netdb.h']
  incl  = ''
  foreach h: hdrs
    incl += cc.has_header(h) ? '#include <' + h + '>\n' : ''
  endforeach
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
  headers += 'sys/types.h'
  headers += 'arpa/nameser.h'
  srcn += 'dns'
  optlist += '+DNS'
  config.set('ENABLE_DNS', 1)
else
  optlist += '-DNS'
  manexcl += 'n'
  manexcl += 'N'
endif
#
ai_idn_hdr = '''
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#ifndef __EXTENSIONS__
#define __EXTENSIONS__ 1
#endif
'''
foreach hdr: ['sys/types.h', 'sys/socket.h', 'netdb.h']
  ai_idn_hdr += cc.has_header(hdr)  ? '\n#include <' + hdr + '>'  : ''
endforeach
idn = cc.get_define('AI_IDN', prefix: ai_idn_hdr) != ''
#
if not idn # no getaddrinfo() with AI_IDN flag
  foreach lib: ['idn2', 'idn']
    dep = dependency('lib' + lib, required: false)
    idn = dep.found()
    if not idn
      dep = cc.find_library(lib, required: false)
      idn = dep.found()
    endif
    if idn
      config.set('LIB' + lib.to_upper(), 1)
      if (lib == 'idn2')
        headers += lib / lib + '.h'
      endif
      deps += dep
      break
    endif
  endforeach
endif
optlist += idn ? '+IDN' : '-IDN'
#
if ipinfo
  srcn += 'ipinfo'
  optlist += '+IPINFO'
  config.set('WITH_IPINFO', 1)
else
  optlist += '-IPINFO'
  manexcl += 'l'
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
foreach fn, desc: fndesc
  libs   = desc['libs']
  incl   = ''
  hdr    = 'hdr' in desc ? desc['hdr'] : ''
  if hdr != ''
    incl += cc.has_header(hdr) ? '#include <' + hdr + '>' : ''
  endif
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
if cc.get_define('IP_TOS',
  prefix: cc.has_header('netinet/in.h') ? '#include <netinet/in.h>' : ''
) == ''
  manexcl += 'q'
endif
# retest headers with optional ones
foreach h: headers
  if cc.has_header(h)
    config.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach
#

if meson.version().version_compare('>=0.53')
  summary({'CAP': cap, 'CURSES': curses, 'UNICODE': unicode, 'NLS': nls,
   'DNS': dns, 'IDN': idn, 'IPINFO': ipinfo, 'SPLIT': split, 'IPV6': ipv6, 'MPLS': mpls},
    bool_yn: true)
endif

# fin
#
config_h = 'config.h'
configure_file(output: config_h, configuration: config)
add_project_arguments('-include', config_h, language: 'c')
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

