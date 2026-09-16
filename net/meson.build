
# NET part of mtr085-meson

srcf += files('net.c')
srcf += files('gen.c')

if raw # socket type raw/user
  optlist += 'SOCKET=raw'
  srcf    += files('raw.c')
  config.set('USE_RAW', 1)
  # libcap: mandatory on linux
  lib = 'cap'
  libcap = dependency('lib' + lib, required: false)
  cap = libcap.found()
  req = os == 'linux'
  if not cap
    libcap = cc.find_library(lib, required: req)
    cap = libcap.found()
  endif
  if cap
    deps += libcap
    config.set('LIBCAP', 1)
    optlist += '+CAP'
  else
    optlist += '-CAP'
  endif
else
  optlist += 'SOCKET=user'
  srcf    += files('user.c')
  srcf    += files('linux-exterr.c')
  manexcl += 't' # user-socket tcp-mode is not ready yet
  manexcl += 'T'
  manexcl += 'p'
endif

fndesc += {'pow': {'hdr': 'math.h', 'libs': ['m']}}
fndesc += {'arc4random_uniform': {'hdr': 'stdlib.h', 'req': false, 'libhdr': true}}

