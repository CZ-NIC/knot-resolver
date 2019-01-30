project(
  'knot-resolver',
  ['c', 'cpp'],
  license: 'GPLv3+',
  version: '3.2.1',  # TODO dev version from git
  default_options: ['c_std=c99'],  # TODO why not c11?
)


# Project-wide dependencies

knot_version = '>=2.7.6'
libknot = dependency('libknot', version: knot_version)
libdnssec = dependency('libdnssec', version: knot_version)
libzscanner = dependency('libzscanner', version: knot_version)
libuv = dependency('libuv', version: '>=1.7')
lmdb = dependency('lmdb')
gnutls = dependency('gnutls')
luajit = dependency('luajit')


# Optional dependencies

## tests
cmocka = dependency('cmocka', required: false)
socket_wrapper = dependency('socket_wrapper', required: false)

## coverage
lcov = find_program('lcov', required: false)
luacov = find_program('luacov', required: false)


# Variables

libkres_soversion = 9

if get_option('modules_dir') == ''
  modules_dir = join_paths(
    get_option('prefix'), get_option('libdir'), 'knot-resolver')
else
  modules_dir = get_option('modules_dir')
endif
message('modules_dir: ' + modules_dir)

data_dir = join_paths(get_option('prefix'), get_option('datadir'), 'knot-resolver')
doc_dir = join_paths(get_option('prefix'), get_option('datadir'), 'doc', 'knot-resolver')
etc_dir = join_paths(get_option('prefix'), get_option('sysconfdir'), 'knot-resolver')

config = configuration_data()
config.set('keyfile_default', get_option('keyfile_default'))
config.set('etc_dir', etc_dir)

# TODO @DATE@. @VERSION@, ...

add_global_arguments(
  '-D_GNU_SOURCE',
  '-Wtype-limits',
  '-Wformat',
  '-Wformat-security',
  '-Wshadow',
  '-Wall',
  '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
  '-DPREFIX="@0@"'.format(get_option('prefix')),
  '-DMODULEDIR="@0@"'.format(modules_dir),
  '-fvisibility=hidden',
  language: 'c',
)


# compile
subdir('contrib')
subdir('lib')
subdir('client')
subdir('daemon')
subdir('modules')


# documentation, install, tests
# TODO install man
subdir('doc')
subdir('etc')
