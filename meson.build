project(
  'knot-resolver',
  ['c', 'cpp'],
  license: 'GPLv3+',
  version: '3.2.1',
  default_options: ['c_std=c99', 'b_ndebug=if-release'],
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

libext = '.so'
if host_machine.system() == 'darwin'
  libext = '.dylib'
endif

## Paths
prefix = get_option('prefix')
data_dir = join_paths(prefix, get_option('datadir'), 'knot-resolver')
doc_dir = join_paths(prefix, get_option('datadir'), 'doc', 'knot-resolver')
examples_dir = join_paths(doc_dir, 'examples')
etc_dir = join_paths(prefix, get_option('sysconfdir'), 'knot-resolver')
lib_dir = join_paths(prefix, get_option('libdir'), 'knot-resolver')
modules_dir = join_paths(lib_dir, 'kres_modules')
sbin_dir = join_paths(prefix, get_option('sbindir'))
systemd_work_dir = ''
run_dir = ''
systemd_unit_dir = ''
systemd_tmpfiles_dir = ''

## Trust anchors
managed_ta = get_option('managed_ta').enabled()
keyfile_default = join_paths(etc_dir, get_option('keyfile_default'))
if keyfile_default == join_paths(etc_dir, 'root.keys')
  install_root_keys = true
  managed_ta = managed_ta or get_option('managed_ta').auto()
else
  install_root_keys = false
  if managed_ta
    warning('Using managed_ta along with non-standard keyfile_default. ' +
	    'Ensure keyfile_default directory will be writable by kresd.')
  endif
endif

## Root hints
root_hints = join_paths(etc_dir, get_option('root_hints'))
if root_hints == join_paths(etc_dir, 'root.hints')
  install_root_hints = true
else
  install_root_hints = false
endif

## Additional options
opt_verbose_log = get_option('verbose_log')
verbose_log = opt_verbose_log.enabled() or opt_verbose_log.auto()
user = get_option('user')
group = get_option('group')

## Systemd
message('--- systemd socket activation ---')
libsystemd = dependency('libsystemd', version: '>=227', required: false)
systemd_unit_files = get_option('systemd_unit_files')
if systemd_unit_files == 'enabled' and not libsystemd.found()
  error('systemd_unit_files=enabled requires libsystemd >= 227')
endif
message('---------------------------')

## Compiler args
add_project_arguments(
  '-D_GNU_SOURCE',
  '-Wformat-security',
  '-Wtype-limits',
  '-Wshadow',
  '-Wall',
  '-fvisibility=hidden',
  language: 'c',
)

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


# kresconfig.h
conf_data = configuration_data()
conf_data.set_quoted('PACKAGE_VERSION', meson.project_version())
conf_data.set_quoted('LIBDIR', lib_dir)
conf_data.set_quoted('ROOTHINTS', root_hints)
conf_data.set_quoted('LIBEXT', libext)
conf_data.set_quoted('libzscanner_SONAME',
  libzscanner.get_pkgconfig_variable('soname'))
conf_data.set_quoted('libknot_SONAME',
  libknot.get_pkgconfig_variable('soname'))
conf_data.set('HAS_SYSTEMD', libsystemd.found())
conf_data.set('NOVERBOSELOG', not verbose_log)

kresconfig = configure_file(
  output: 'kresconfig.h',
  configuration: conf_data,
)

kresconfig_dep = declare_dependency(
  sources: kresconfig,
  include_directories: include_directories('.'),
)


# Compile
## Dependencies first
subdir('contrib')
subdir('lib')

## Remaining code
subdir('client')
subdir('daemon')
subdir('modules')
if get_option('bench').enabled()
  subdir('bench')
endif


# Tests
subdir('tests')


# Documentation & configs
subdir('doc')
subdir('etc')


# Systemd unit files
if systemd_unit_files != 'disabled'
  subdir('systemd')
endif

# Additional files
install_data(
  sources: [
    'AUTHORS',
    'COPYING',
    'NEWS',
  ],
  install_dir: doc_dir,
)


# Summary message
# NOTE: ternary operator in format() not supported
# https://github.com/mesonbuild/meson/issues/2404
s_managed_ta = managed_ta ? 'enabled' : 'disabled'
s_systemd_socket = libsystemd.found() ? 'enabled' : 'disabled'
s_build_client = build_client ? 'enabled' : 'disabled'
s_build_doc = build_doc ? 'enabled' : 'disabled'
s_build_postinstall_tests = build_postinstall_tests ? 'enabled' : 'disabled'
s_build_unit_tests = build_unit_tests ? 'enabled' : 'disabled'
s_install_kresd_conf = install_kresd_conf ? 'enabled' : 'disabled'
message('''

======================= SUMMARY =======================

  paths
    prefix:             @0@'''.format(prefix) + '''
    lib_dir:            @0@'''.format(lib_dir) + '''
    sbin_dir:           @0@'''.format(sbin_dir) + '''
    etc_dir:            @0@'''.format(etc_dir) + '''
    root.hints:         @0@'''.format(root_hints) + '''

  trust_anchors
    keyfile_default:    @0@'''.format(keyfile_default) + '''
    managed_ta:         @0@'''.format(s_managed_ta) + '''

  systemd:
    socket activation:  @0@'''.format(s_systemd_socket) + '''
    unit_files:         @0@'''.format(systemd_unit_files) + '''
    work_dir:           @0@'''.format(systemd_work_dir) + '''

  optional components
    client:             @0@'''.format(s_build_client) + '''
    doc:                @0@'''.format(s_build_doc) + '''
    unit_tests:         @0@'''.format(s_build_unit_tests) + '''
    postinstall_tests:  @0@'''.format(s_build_postinstall_tests) + '''

  additional
    user:               @0@'''.format(user) + '''
    group:              @0@'''.format(group) + '''
    install_kresd_conf: @0@'''.format(s_install_kresd_conf) + '''

=======================================================

''')
