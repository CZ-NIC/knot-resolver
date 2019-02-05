project(
  'knot-resolver',
  ['c', 'cpp'],
  license: 'GPLv3+',
  version: '3.2.1',  # TODO dev version from git
  default_options: ['c_std=c99'],
  meson_version: '>=0.47.0',
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


# TODO coverage
#lcov = find_program('lcov', required: false)
#luacov = find_program('luacov', required: false)


# Variables

libkres_soversion = 9

if get_option('modules_dir') == ''
  modules_dir = join_paths(
    get_option('prefix'), get_option('libdir'), 'knot-resolver')
else
  modules_dir = get_option('modules_dir')
endif

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

# List of lua modules to be installed to modules_dir
lua_src = [
  # files(module.lua)
]

# List of tests
# These lists are added to from subdir() and finally used in tests/*

unit_tests = [
  # [test_name, files(test)]
]

config_tests = [
  # [name, files(test)]  # or
  # [name, files(test), [arg1, arg2], should_fail]
]

integr_tests = [
  # [name, test_dir_relative_to_src_root]
]


# NOTE order of subdir includes is significant
# compile
subdir('contrib')
subdir('lib')
subdir('daemon')
subdir('modules')

if get_option('client')
  subdir('client')
endif


# tests
subdir('tests')


# documentation, examples
# TODO install man
subdir('doc')
subdir('etc')


# TODO message summary?
message('modules_dir: ' + modules_dir)
message(kresd_install_path)
