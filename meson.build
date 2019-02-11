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
examples_dir = join_paths(doc_dir, 'examples')
etc_dir = join_paths(prefix, get_option('sysconfdir'), 'knot-resolver')
sbin_dir = join_paths(prefix, get_option('sbindir'))
systemd_work_dir = ''
run_dir = ''
systemd_unit_dir = ''
systemd_tmpfiles_dir = ''

modules_dir = get_option('modules_dir')
if modules_dir == ''
  modules_dir = join_paths(prefix, get_option('libdir'), 'knot-resolver')
endif

## Trust anchors
managed_ta = get_option('managed_ta').enabled()
keyfile_default = get_option('keyfile_default')
if keyfile_default == ''
  keyfile_default = join_paths(etc_dir, 'root.keys')
  install_root_keys = true
  managed_ta = managed_ta or get_option('managed_ta').auto()
else
  install_root_keys = false
  if managed_ta  # TODO does this make sense? hardcoded path is in configs
    warning('Using managed_ta along with keyfile_default. Ensure '
	    + 'keyfile_default will be writable by kresd.')
  endif
endif

## User/Group
user = get_option('user')
group = get_option('group')

## Systemd
opt_systemd = get_option('systemd')
systemd = false
systemd_socket = false
if opt_systemd != 'disabled'
  message('--- systemd integration ---')
  libsystemd = dependency('libsystemd', version: '>=227',
			  required: opt_systemd == 'enabled')
  if libsystemd.found()
    systemd = true
    systemd_socket = opt_systemd != 'nosocket'
  else
    libsystemd = dependency('libsystemd', required: systemd == 'nosocket')
    if libsystemd.found()
      systemd = true
      systemd_socket = false
    endif
  endif
  message('---------------------------')
endif

# TODO use var instead
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
subdir('client')


# tests
subdir('tests')


# documentation, examples
# TODO install man
subdir('doc')
subdir('etc')

# systemd integration
if systemd
  subdir('systemd')
endif


# summary message
# NOTE: ternary operator in format() not supported
# https://github.com/mesonbuild/meson/issues/2404
summary_managed_ta = managed_ta ? 'enabled' : 'disabled'
summary_systemd = systemd ? 'enabled' : 'disabled'
summary_systemd_socket = systemd_socket ? 'enabled' : 'disabled'
summary_build_client = build_client ? 'enabled' : 'disabled'
summary_build_daemon = build_daemon ? 'enabled' : 'disabled'
summary_build_doc = build_doc ? 'enabled' : 'disabled'
summary_build_extra_tests = build_extra_tests ? 'enabled' : 'disabled'
summary_build_unit_tests = build_unit_tests ? 'enabled' : 'disabled'
summary_install_kresd_conf = install_kresd_conf ? 'enabled' : 'disabled'
message('''

======================= SUMMARY =======================

  paths
    prefix:             @0@'''.format(prefix) + '''
    modules_dir:        @0@'''.format(modules_dir) + '''

  trust_anchors
    keyfile_default:    @0@'''.format(keyfile_default) + '''
    managed_ta:         @0@'''.format(summary_managed_ta) + '''

  systemd:              @0@'''.format(summary_systemd) + '''
    socket activation:  @0@'''.format(summary_systemd_socket) + '''
    work_dir:           @0@'''.format(systemd_work_dir) + '''

  components
    client:             @0@'''.format(summary_build_client) + '''
    daemon:             @0@'''.format(summary_build_daemon) + '''
    doc:                @0@'''.format(summary_build_doc) + '''
    extra_tests:        @0@'''.format(summary_build_extra_tests) + '''
    unit_tests:         @0@'''.format(summary_build_unit_tests) + '''

  additional
    user:               @0@'''.format(user) + '''
    group:              @0@'''.format(group) + '''
    install_kresd_conf: @0@'''.format(summary_install_kresd_conf) + '''
    version:            @0@'''.format(meson.project_version()) + '''

=======================================================

''')
