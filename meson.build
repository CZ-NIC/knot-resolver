# SPDX-License-Identifier: GPL-3.0-or-later

project(
  'knot-resolver',
  ['c', 'cpp'],
  license: 'GPLv3+',
  version: '5.4.0',
  default_options: ['c_std=gnu11', 'b_ndebug=true'],
  meson_version: '>=0.49',
)


# Unity build
if get_option('unity') != 'off'
  error('unity builds are not supported! ' +
    'https://gitlab.nic.cz/knot/knot-resolver/issues/460')
endif


message('--- required dependencies ---')
knot_version = '>=2.9'
libknot = dependency('libknot', version: knot_version)
libdnssec = dependency('libdnssec', version: knot_version)
libzscanner = dependency('libzscanner', version: knot_version)
libuv = dependency('libuv', version: '>=1.7')
lmdb = dependency('lmdb', required: false)
if not lmdb.found()  # darwin workaround: missing pkgconfig
  lmdb = meson.get_compiler('c').find_library('lmdb')
endif
gnutls = dependency('gnutls')
luajit = dependency('luajit')
# NOTE avoid using link_args for luajit due to a macOS issue
# https://github.com/Homebrew/homebrew-core/issues/37169
luajit_inc = luajit.partial_dependency(compile_args: true, includes: true)
message('------------------------------')


# Variables
libkres_soversion = 9

libext = '.so'
if host_machine.system() == 'darwin'
  libext = '.dylib'
endif

## Paths
prefix = get_option('prefix')
data_dir = prefix / get_option('datadir') / 'knot-resolver'
doc_dir = prefix / get_option('datadir') / 'doc' / 'knot-resolver'
info_dir = prefix / get_option('datadir') / 'info'
examples_dir = doc_dir / 'examples'
etc_dir = prefix / get_option('sysconfdir') / 'knot-resolver'
lib_dir = prefix / get_option('libdir') / 'knot-resolver'
modules_dir = lib_dir / 'kres_modules'
sbin_dir = prefix / get_option('sbindir')
run_dir = '/run' / 'knot-resolver'
systemd_work_dir = prefix / get_option('localstatedir') / 'lib' / 'knot-resolver'
systemd_cache_dir = prefix / get_option('localstatedir') / 'cache' / 'knot-resolver'
systemd_unit_dir = prefix / 'lib' / 'systemd' / 'system'
systemd_tmpfiles_dir = prefix / 'lib' / 'tmpfiles.d'
systemd_sysusers_dir = prefix / 'lib' / 'sysusers.d'
mod_inc_dir = include_directories('.', 'contrib/')

## Trust anchors
managed_ta = get_option('managed_ta') == 'enabled'
keyfile_default = etc_dir / get_option('keyfile_default')
if keyfile_default == etc_dir / 'root.keys'
  managed_ta = managed_ta or get_option('managed_ta') == 'auto'
endif
install_root_keys = get_option('install_root_keys') == 'enabled'
if get_option('install_root_keys') == 'auto'
  install_root_keys = managed_ta
endif


## Root hints
root_hints = etc_dir / get_option('root_hints')
if root_hints == etc_dir / 'root.hints'
  install_root_hints = true
else
  install_root_hints = false
endif

## Additional options
user = get_option('user')
group = get_option('group')

## Optional dependencies
message('--- optional dependencies ---')
nghttp2 = dependency('libnghttp2', required: false)
openssl = dependency('openssl', required: false)

have_asprintf = meson.get_compiler('c').has_function('asprintf',
  prefix: '#define _GNU_SOURCE\n#include <stdio.h>')

### capng
# use empty name to disable the dependency, but still compile the dependent kresd
capng_name = get_option('capng') == 'disabled' ? '' : 'libcap-ng'
capng = dependency(capng_name, required: get_option('capng') == 'enabled')

### sendmmsg
has_sendmmsg = meson.get_compiler('c').has_function('sendmmsg',
  prefix: '#define _GNU_SOURCE\n#include <sys/socket.h>')
if get_option('sendmmsg') == 'enabled' and not has_sendmmsg
  error('missing compiler function: sendmmsg(), use -Dsendmmsg=disabled')
elif get_option('sendmmsg') == 'auto'
  sendmmsg = has_sendmmsg
else
  sendmmsg = get_option('sendmmsg') == 'enabled'
endif

### XDP: not configurable - we just check if libknot supports it
xdp = meson.get_compiler('c').has_header('libknot/xdp/xdp.h'
    ) and libknot.version().version_compare('>= 3.0.2')

### Systemd
systemd_files = get_option('systemd_files')
libsystemd = dependency('libsystemd', required: systemd_files == 'enabled')
message('---------------------------')

## Compiler args
add_project_arguments(
  '-D_GNU_SOURCE',
  '-Wformat',
  '-Wformat-security',
  '-Wtype-limits',
  '-Wshadow',
  '-Werror=implicit-function-declaration', # Probably messed up includes; implicit functions are evil!
  '-Werror=attributes',  # Missing cleanup attribute could lead to memory leaks.
  '-fvisibility=hidden',
  '-DHAVE_ASPRINTF=' + have_asprintf.to_int().to_string(),

  # libuv handles have aliasing problems; see:
  # https://github.com/libuv/libuv/pull/2588/files#diff-04c6e90faac2675aa89e2176d2eec7d8
  # https://github.com/libuv/libuv/issues/1230#issuecomment-569030944
  # Performance impact in our case seems OK:
  # https://gitlab.nic.cz/knot/knot-resolver/-/merge_requests/962#note_147407
  '-fno-strict-aliasing',

  language: 'c',
)

# Files for clang-tidy lint
c_src_lint = files()

# Lists of tests
# These lists are added to from subdir() and finally used in tests/*

unit_tests = [
  # [test_name, files(test)]
]

config_tests = [
  # [name, files(test)]  # or
  # [name, files(test), [extra_suites]]
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
conf_data.set_quoted('OPERATING_SYSTEM', host_machine.system())
conf_data.set_quoted('libzscanner_SONAME',
  libzscanner.get_pkgconfig_variable('soname'))
conf_data.set_quoted('libknot_SONAME',
  libknot.get_pkgconfig_variable('soname'))
conf_data.set('ENABLE_LIBSYSTEMD', libsystemd.found().to_int())
conf_data.set('ENABLE_SENDMMSG', sendmmsg.to_int())
conf_data.set('ENABLE_XDP', xdp.to_int())
conf_data.set('ENABLE_CAP_NG', capng.found().to_int())
conf_data.set('ENABLE_DOH2', nghttp2.found().to_int())
conf_data.set('DBG_ASSERTION_ABORT', get_option('debug').to_int())
if get_option('debug')
  conf_data.set('DBG_ASSERTION_FORK', '0')
else
  conf_data.set('DBG_ASSERTION_FORK', '(5 * 60 * 1000) /* five minutes */')
endif

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
subdir('daemon')
subdir('modules')
subdir('utils')
if get_option('bench') == 'enabled'
  subdir('bench')
endif


# Tests
subdir('tests')


# Documentation & configs
subdir('doc')
subdir('etc')


# Systemd unit files
if systemd_files != 'disabled'
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


# Lint
message('--- lint dependencies ---')
clangtidy = find_program('clang-tidy', required: false)
luacheck = find_program('luacheck', required: false)
flake8 = find_program('flake8', required: false)
pylint_run = find_program('scripts/run-pylint.sh')
message('-------------------------')

if clangtidy.found()
  run_target(
    'tidy',
    command: [
      clangtidy,
      '-quiet',
      '-p', meson.build_root(),
    ] + c_src_lint
  )
endif

if luacheck.found()
  run_target(
    'luacheck',
    command: [
      luacheck,
      '--codes',
      '--formatter', 'TAP',
      meson.source_root(),
    ],
  )
endif

if flake8.found()
  run_target(
    'flake8',
    command: [
      flake8,
      '--max-line-length=100',
      meson.source_root() / 'tests' / 'pytests',
    ],
  )
endif

run_target(
  'pylint',
  command: pylint_run,
)


# Summary message
# NOTE: ternary operator in format() not supported
# https://github.com/mesonbuild/meson/issues/2404
s_managed_ta = managed_ta ? 'enabled' : 'disabled'
s_install_root_keys = install_root_keys ? 'enabled' : 'disabled'
s_build_client = build_client ? 'enabled' : 'disabled'
s_build_utils = build_utils ? 'enabled' : 'disabled'
s_build_dnstap = build_dnstap ? 'enabled' : 'disabled'
s_build_unit_tests = build_unit_tests ? 'enabled' : 'disabled'
s_build_config_tests = build_config_tests ? 'enabled' : 'disabled'
s_build_extra_tests = build_extra_tests ? 'enabled' : 'disabled'
s_install_kresd_conf = install_kresd_conf ? 'enabled' : 'disabled'
s_sendmmsg = sendmmsg ? 'enabled': 'disabled'
s_xdp = xdp ? 'enabled': 'disabled'
s_openssl = openssl.found() ? 'present': 'missing'
s_capng = capng.found() ? 'enabled': 'disabled'
s_doh2 = nghttp2.found() ? 'enabled': 'disabled'
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
    install_root_keys:  @0@'''.format(s_install_root_keys) + '''

  systemd:
    files:              @0@'''.format(systemd_files) + '''
    work_dir:           @0@'''.format(systemd_work_dir) + '''
    cache_dir:          @0@'''.format(systemd_cache_dir) + '''

  optional components
    client:             @0@'''.format(s_build_client) + '''
    utils:              @0@'''.format(s_build_utils) + '''
    dnstap:             @0@'''.format(s_build_dnstap) + '''
    unit_tests:         @0@'''.format(s_build_unit_tests) + '''
    config_tests:       @0@'''.format(s_build_config_tests) + '''
    extra_tests:        @0@'''.format(s_build_extra_tests) + '''

  additional
    user:               @0@'''.format(user) + '''
    group:              @0@'''.format(group) + '''
    install_kresd_conf: @0@'''.format(s_install_kresd_conf) + '''
    sendmmsg:           @0@'''.format(s_sendmmsg) + '''
    XDP (in libknot):   @0@'''.format(s_xdp) + '''
    openssl debug:      @0@'''.format(s_openssl) + '''
    capng:              @0@'''.format(s_capng) + '''
    doh2:               @0@'''.format(s_doh2) + '''

=======================================================

''')
