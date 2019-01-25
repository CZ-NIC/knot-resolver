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

# Optional dependencies

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


# Variables

# TODO @DATE@. @VERSION@, ...

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


subdir('contrib')
subdir('lib')
subdir('client')
subdir('daemon')

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

#library(
#  'stats',
#  ['modules/stats/stats.c'],
#  dependencies: [
#    contrib_dep,
#    libkres_dep,
#    luajit,
#  ],
#  install: true,
#  install_dir: modules_dir,
#  name_prefix: '',
#)

# TODO: dnstap


# install

## install lua modules
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

foreach mod : lua_modules_daemon
  install_data(
    join_paths('daemon', 'lua', mod + '.lua'),
    install_dir: modules_dir,
  )
endforeach

install_data(
  'modules/daf/daf.js',
  install_dir: join_paths(modules_dir, 'daf'),
)


# etc

install_data(sources: 'etc/root.hints', install_dir: get_option('sysconfdir'))
