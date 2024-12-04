# SPDX-License-Identifier: GPL-3.0-or-later

project(
  'knot-resolver',
  ['c', 'cpp'],
  license: 'GPLv3+',
  version: '6.0.9',
  default_options: ['c_std=gnu11', 'b_ndebug=true'],
  meson_version: '>=0.49',
)


# Unity build
if get_option('unity') != 'off'
  error('unity builds are not supported! ' +
    'https://gitlab.nic.cz/knot/knot-resolver/issues/460')
endif


message('--- required dependencies ---')
knot_version = '>=3.3'
libknot = dependency('libknot', version: knot_version)
libdnssec = dependency('libdnssec', version: knot_version)
libzscanner = dependency('libzscanner', version: knot_version)
libuv = dependency('libuv', version: '>=1.27')  # need uv_udp_connect()
lmdb = dependency('lmdb', required: false)
if not lmdb.found()  # darwin workaround: missing pkgconfig
  lmdb = meson.get_compiler('c').find_library('lmdb')
endif
gnutls = dependency('gnutls', version: '>=3.4')
luajit = dependency('luajit')
# https://mesonbuild.com/howtox.html#add-math-library-lm-portably
libm = meson.get_compiler('c').find_library('m', required : false)
message('------------------------------')


# Variables
auto_prefixes = ['/', '/usr', '/usr/local']
libkres_soversion = 9

libext = '.so'
if host_machine.system() == 'darwin'
  libext = '.dylib'
elif host_machine.system() == 'cygwin'
  libext = '.dll'
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
bin_dir = prefix / get_option('bindir')
if host_machine.system() == 'linux'
  # When installing from sources with a non-standard prefix,
  # we need to set the correct run directory with the prefix,
  # otherwise rwx permissions will fail with a validation error
  # on the run directory
  if prefix in auto_prefixes
    run_dir = '/run' / 'knot-resolver'
  else
    run_dir = prefix / 'run' / 'knot-resolver'
  endif
elif host_machine.system() == 'darwin'
  run_dir = prefix / get_option('localstatedir') / 'run' / 'knot-resolver'
else
  run_dir = get_option('localstatedir') / 'run' / 'knot-resolver'
endif
systemd_work_dir = prefix / get_option('localstatedir') / 'lib' / 'knot-resolver'
systemd_cache_dir = prefix / get_option('localstatedir') / 'cache' / 'knot-resolver'
systemd_unit_dir = prefix / 'lib' / 'systemd' / 'system'
systemd_tmpfiles_dir = prefix / 'lib' / 'tmpfiles.d'
systemd_sysusers_dir = prefix / 'lib' / 'sysusers.d'
completion_dir = prefix / 'share'

## RPath
# When installing from sources into a non-standard prefix and the library is
# shared/dynamic, we need to set the executables' RPATH so that they can find
# `libkresd`, otherwise running them will fail with dynamic linkage errors
rpath_opt = get_option('install_rpath')
if (get_option('default_library') == 'static' or
    rpath_opt == 'disabled' or
    (rpath_opt == 'auto' and prefix in auto_prefixes))
  rpath = ''
else
  rpath = prefix / get_option('libdir')
endif

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
xdp = meson.get_compiler('c').has_header('libknot/xdp/xdp.h')

### Systemd
systemd_files = get_option('systemd_files')
systemd_legacy_units = get_option('systemd_legacy_units')
libsystemd = dependency('libsystemd', required: systemd_files == 'enabled')

# Uh, lifted this trivial line from tests/meson.build due to dependency sorting:
build_extra_tests = get_option('extra_tests') == 'enabled'

### Allocator
# use empty name to disable the dependency, but still compile the dependent kresd
malloc_name = ''
if get_option('malloc') == 'jemalloc' or (get_option('malloc') == 'auto' and not build_extra_tests)
  malloc_name = 'jemalloc'
endif
malloc = meson.get_compiler('c').find_library(
  malloc_name,
  required: get_option('malloc') == 'jemalloc',
  #static: false, #TODO: add when bumping meson to >= 0.51;
  # static linking would most likely cause issues.
  # Fortunately it seems unlikely that dynamic wouldn't be found and static would be.
)

message('---------------------------')

## Compiler args
add_project_arguments(
  '-D_GNU_SOURCE',

  # Various warnings.  Let's use any warning that doesn't "cause problems".
  '-Wall',
  '-Wformat',
  '-Wformat-security',
  '-Wtype-limits',
  '-Wshadow',
  '-Werror=implicit-function-declaration', # Probably messed up includes; implicit functions are evil!
  '-Werror=attributes',  # Missing cleanup attribute could lead to memory leaks.
  '-Wstrict-prototypes', # `void foo();` is basically always a mistake, in our code at least.
  '-Wold-style-definition',
  '-Wignored-qualifiers',
  '-Woverride-init',
  '-Wuninitialized',

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

if meson.get_compiler('c').get_id() == 'gcc'
  add_project_arguments(
    '-Wno-nonnull-compare', # reasonable to do in assertions
    language: 'c',
  )
endif

# Files for clang-tidy lint
c_src_lint = files()

# Lists of tests
# These lists are added to from subdir() and finally used in tests/*

unit_tests = [
  # [name, files(test)]
  # [name, files(test), [extra_suites]]
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
conf_data.set('ENABLE_LIBSYSTEMD', libsystemd.found().to_int())
conf_data.set('ENABLE_SENDMMSG', sendmmsg.to_int())
conf_data.set('ENABLE_XDP', xdp.to_int())
conf_data.set('ENABLE_CAP_NG', capng.found().to_int())
conf_data.set('ENABLE_JEMALLOC', malloc.found().to_int())
conf_data.set('ENABLE_DOH2', nghttp2.found().to_int())
conf_data.set('DBG_ASSERTION_ABORT', get_option('debug').to_int())
if get_option('debug')
  conf_data.set('DBG_ASSERTION_FORK', '0')
else
  conf_data.set('DBG_ASSERTION_FORK', '(5 * 60 * 1000) /* five minutes */')
endif

# Getting *runtime* path to knot-dns libs is surprisingly difficult.
# Partially it's because meson isn't meant for general-purpose programming.
foreach libname, lib: { 'libknot': libknot, 'libzscanner': libzscanner }
  l = lib.get_pkgconfig_variable('libdir')
  p = lib.get_pkgconfig_variable('prefix')
  ep = lib.get_pkgconfig_variable('exec_prefix')
  if ep != p # replace `p` with `ep` at the start of `l`
    assert(l.startswith(p))
    p_len = run_command('sh', '-c', 'echo "' + p + '" | wc -c', check: true).stdout().to_int()
    l = ep / l.substring(p_len)
  endif
  conf_data.set_quoted(libname + '_SONAME', l / lib.get_pkgconfig_variable('soname'))
endforeach

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
subdir('python' / 'knot_resolver')
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
subdir('systemd')


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
message('-------------------------')

if clangtidy.found()
  run_target(
    'tidy',
    command: [
      clangtidy,
      '-quiet',
      '-extra-arg=-Wno-unknown-warning-option', # version in CI is weird in this
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


# Summary message
# NOTE: ternary operator in format() not supported
# https://github.com/mesonbuild/meson/issues/2404
s_managed_ta = managed_ta ? 'enabled' : 'disabled'
s_install_root_keys = install_root_keys ? 'enabled' : 'disabled'
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
s_malloc = malloc.found() ? 'jemalloc' : 'libc default'
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
    malloc:             @0@'''.format(s_malloc) + '''
    doh2:               @0@'''.format(s_doh2) + '''

=======================================================

''')
