project(
  'knot-resolver',
  ['c', 'cpp'],
  license: 'GPLv3+',
  version: '3.2.1',
  default_options: ['c_std=c99'],
  meson_version: '>=0.47.0',
)


message('--- required dependencies ---')
knot_version = '>=2.7.6'
libknot = dependency('libknot', version: knot_version)
libdnssec = dependency('libdnssec', version: knot_version)
libzscanner = dependency('libzscanner', version: knot_version)
libuv = dependency('libuv', version: '>=1.7')
lmdb = dependency('lmdb')
gnutls = dependency('gnutls')
luajit = dependency('luajit')
message('------------------------------')


# TODO coverage
#lcov = find_program('lcov', required: false)
#luacov = find_program('luacov', required: false)

# TODO lint


# Variables
libkres_soversion = 9

## Paths
prefix = get_option('prefix')
data_dir = join_paths(prefix, get_option('datadir'), 'knot-resolver')
doc_dir = join_paths(prefix, get_option('datadir'), 'doc', 'knot-resolver')
etc_dir = join_paths(prefix, get_option('sysconfdir'), 'knot-resolver')
sbin_dir = join_paths(prefix, get_option('sbindir'))

modules_dir = get_option('modules_dir')
if modules_dir == ''
  modules_dir = join_paths(prefix, get_option('libdir'), 'knot-resolver')
endif

## Trust anchors
managed_ta = get_option('managed_ta').enabled()
kefyile_default = get_option('keyfile_default')
if keyfile_default == ''
  keyfile_default = join_paths(etc_dir, 'root.keys')
  install_root_keys = true
  managed_ta = managed_ta or get_option('managed_ta').auto()
else
  install_root_keys = false
  if managed_ta
    warning('Using managed_ta along with keyfile_default. Ensure '
	    'keyfile_default will be writable by kresd.')
  endif
endif

## Configuration (for *.in files)
config = configuration_data()
config.set('keyfile_default', get_option('keyfile_default'))
config.set('modules_dir', etc_dir)
config.set('etc_dir', etc_dir)
config.set('man_seealso_systemd', '')
config.set('version', meson.project_version())
config.set('date', run_command('scripts/get-date.sh', check: true).stdout().strip())


add_global_arguments(
  '-D_GNU_SOURCE',
  '-Wtype-limits',
  '-Wformat',
  '-Wformat-security',
  '-Wshadow',
  '-Wall',
  '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
  '-DPREFIX="@0@"'.format(prefix),
  '-DMODULEDIR="@0@"'.format(modules_dir),
  '-fvisibility=hidden',
  language: 'c',
)

# List of lua modules to be installed to modules_dir
lua_src = [
  # files(module.lua)
]

# Lists of tests
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


# NOTE "dist" target is explicitly not supported for two reasons
#   1) we use meson test to run integration / postinstall tests
#   2) we want custom version number, not the hard-coded string in project()
# Use "archive" target instead
run_target(
  'archive',
  output: 'archive',
  command: [
    'scripts/make-archive.sh',
    meson.project_version(),
  ],
)


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
message('version: @0@'.format(config.get('version')))
message('date: @0@'.format(config.get('date')))
