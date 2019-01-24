project(
  'knot-resolver', 'c',
  license: 'GPLv3+',
  version: '3.2.1',  # TODO dev version from git
  default_options: ['c_std=c99'],  # TODO why not c11?
)

libkres_soversion = 9
# TODO change modules_dir to sensible lua(jit) default
modules_dir = join_paths(get_option('libdir'), 'kdns_modules')


# Project-wide dependencies

knot_version = '>=2.7.6'
libknot = dependency('libknot', version: knot_version)
libdnssec = dependency('libdnssec', version: knot_version)
libzscanner = dependency('libzscanner', version: knot_version)
libuv = dependency('libuv', version: '>=1.7')
lmdb = dependency('lmdb')
gnutls = dependency('gnutls')
luajit = dependency('luajit')

xxd = find_program('xxd', required: false)
if not xxd.found()
  hexdump = find_program('hexdump')
endif


# Optional dependencies

## systemd socket activation
libsystemd = dependency('libsystemd', version: '>=227', required: false)

## documentation
doxygen = find_program('doxygen', required: false)
sphinx_build = find_program('sphinx-build', required: false)
python_breathe = run_command(
  'python3', ['-c', 'import breathe']).returncode() == 0
if not python_breathe
  warning('python: breathe not found')
endif

## tests
cmocka = dependency('cmocka', required: false)
socket_wrapper = dependency('socket_wrapper', required: false)

## dnstap
libprotobuf_c = dependency('libprotobuf-c', version: '>=1', required: false)
libfstrm = dependency('libfstrm', version: '>=0.2', required: false)
protoc_c = find_program('protoc-c', required: false)

## coverage
lcov = find_program('lcov', required: false)
luacov = find_program('luacov', required: false)

## lua socket
lua_ltn12 = run_command(
  'luajit', ['-l', 'ltn12', '-e', 'os.exit(0)']).returncode() == 0
if not lua_ltn12
  warning('lua: ltn12 not found')
endif

lua_ssl_https = run_command(
  'luajit', ['-l', 'ssl.https', '-e', 'os.exit(0)']).returncode() == 0
if not lua_ssl_https
  warning('lua: ssl.https not found')
endif

# TODO why isn't libedit required instead?
libedit = dependency('libedit', required: false)
if not libedit.found()
  libedit = meson.get_compiler('c').find_library('edit')
endif


# Variables

luajit_has_setfuncs = run_command(
  'pkg-config', ['luajit', '--atleast-version', '2.1.0-beta3']
  ).returncode() == 0 ? '1' : '0'

# TODO @DATE@. @VERSION@, ...

lib_suffix = '.so'
# TODO seek&destroy LIBEXT
if host_machine.system() == 'darwin'
  lib_suffix = '.dylib'
endif

add_global_arguments(
  '-D_GNU_SOURCE',
#  '-Wtype-limits',
#  '-Wformat',
#  '-Wformat-security',
#  '-Wshadow',
#  '-Wall',
  '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
  '-DPREFIX="@0@"'.format(get_option('prefix')),
  '-DMODULEDIR="@0@"'.format(modules_dir),
  '-fvisibility=hidden',
  language: 'c',
)

add_global_link_arguments(
  '-ldl',
  '-lm',
  '-Wl,--export-dynamic',
  language: 'c',
)

c_args = [
  '-fPIE',  # TODO pie=true since 0.49.0
  '-DROOTHINTS="@0@/root.hints"'.format(
      join_paths(get_option('prefix'), get_option('sysconfdir'))),
  '-DLIBEXT="@0@"'.format(lib_suffix),
  '-Dlibzscanner_SONAME="@0@"'.format(libzscanner.get_pkgconfig_variable('soname')),
  '-Dlibknot_SONAME="@0@"'.format(libknot.get_pkgconfig_variable('soname')),
  '-DLUA_HAS_SETFUNCS=@0@'.format(luajit_has_setfuncs),
]

if libsystemd.found()
  c_args += ['-DHAS_SYSTEMD']
endif

if host_machine.system() == 'darwin'
  # luajit workaround for OS X  https://luajit.org/install.html#embed
  c_args += ['-pagezero_size', '10000', '-image_base', '100000000']
endif


subdir('contrib')
subdir('lib')
subdir('client')


## kresd

embed_lua = generator(
  find_program('scripts/embed-lua.sh'),
  arguments: ['@INPUT@'],
  output: '@BASENAME@.inc',
  capture: true,
)

kresd_lua = embed_lua.process(
  'daemon/lua/sandbox.lua',
  'daemon/lua/config.lua',
  preserve_path_from: meson.current_source_dir(),  # TODO is this necessary?
)

kresd_sources = [
  'daemon/bindings.c',
  'daemon/engine.c',
  'daemon/ffimodule.c',
  'daemon/io.c',
  'daemon/main.c',
  'daemon/network.c',
  'daemon/session.c',
  'daemon/tls.c',
  'daemon/tls_ephemeral_credentials.c',
  'daemon/tls_session_ticket-srv.c',
  'daemon/worker.c',
  'daemon/zimport.c',
]

kresd = executable(
  'kresd',
  kresd_sources, kresd_lua,
  include_directories: include_directories('daemon'),
  dependencies: [
    contrib_dep,
    libkres_dep,
    libknot,
    libzscanner,
    libdnssec,
    libuv,
    luajit,
    gnutls,
    libsystemd,
  ],
  c_args: c_args,
  install: true,
  install_dir: 'sbin',
)

# TODO install man

## modules


#library(
#  'bogus_log',
#  ['modules/bogus_log/bogus_log.c'],
#  dependencies: [
#    contrib_dep,
#    libkres_dep,
#    libknot,
#    luajit,
#    libuv,
#  ],
#  install: true,
#  install_dir: modules_dir,
#  name_prefix: '',
#)

#library(
#  'hints',
#  ['modules/hints/hints.c'],
#  dependencies: [
#    contrib_dep,
#    libkres_dep,
#    luajit,
#  ],
#  install: true,
#  install_dir: modules_dir,
#  name_prefix: '',
#)

library(
  'stats',
  ['modules/stats/stats.c'],
  dependencies: [
    contrib_dep,
    libkres_dep,
    luajit,
  ],
  install: true,
  install_dir: modules_dir,
  name_prefix: '',
)

# TODO: dnstap

lua_modules = [
  'daf',
  'detect_time_jump',
  'detect_time_skew',
  'dns64',
  'etcd',
  'graphite',
  'http',
  'policy',
  'predict',
  'prefill',
  'priming',
  'rebinding',
  'renumber',
  'serve_stale',
  'ta_sentinel',
  'ta_signal_query',
  'view',
  'workarounds',
]

foreach mod : lua_modules
  install_data(
    join_paths('modules', mod, mod + '.lua'),
    install_dir: modules_dir,
  )
endforeach

install_data(
  'modules/daf/daf.js',
  install_dir: join_paths(modules_dir, 'daf'),
)


# etc

install_data(sources: 'etc/root.hints', install_dir: get_option('sysconfdir'))
