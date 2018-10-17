project(
  'knot-resolver', 'c',
  license: 'GPLv3+',
  version: '3.0.0',
  default_options: ['c_std=c11'],
)

libkres_soversion = 8
modules_dir = join_paths(get_option('libdir'), 'kdns_modules')

# dependencies

knot_version = '>=2.7.1'
libknot = dependency('libknot', version: knot_version)
libdnssec = dependency('libdnssec', version: knot_version)
libzscanner = dependency('libzscanner', version: knot_version)

libuv = dependency('libuv', version: '>=1.0')

lmdb = dependency('lmdb', required: false)
gnutls = dependency('gnutls')
nettle = dependency('nettle')

lua = dependency('lua', required: false)
if not lua.found()
  lua = dependency('luajit')
endif

libedit = dependency('libedit', required: false)
if not libedit.found()
  libedit = meson.get_compiler('c').find_library('edit')
endif

doxygen = find_program('doxygen', required: false)
sphinx_build = find_program('sphinx-build', required: false)

# $(eval $(call find_luapkg,ltn12))
# $(eval $(call find_luapkg,ssl.https))
# $(eval $(call find_pythonpkg,breathe))

cmocka = dependency('cmocka', required: false)
socket_wrapper = dependency('socket_wrapper', required: false)
libsystemd = dependency('libsystemd', version: '>=227', required: false)
libprotobuf_c = dependency('libprotobuf-c', version: '>=1', required: false)
libfstrm = dependency('libfstrm', version: '>=0.2', required: false)

protoc_c = find_program('protoc-c', required: false)
lcov = find_program('lcov', required: false)
luacov = find_program('luacov', required: false)

## contrib

contrib_sources = [
  'contrib/ccan/asprintf/asprintf.c',
  'contrib/ccan/ilog/ilog.c',
  'contrib/ccan/isaac/isaac.c',
  'contrib/ccan/json/json.c',
  'contrib/ucw/mempool.c',
  'contrib/ucw/mempool-fmt.c',
  'contrib/murmurhash3/murmurhash3.c',
  'contrib/base32hex.c',
  'contrib/base64.c'
]

contrib_includes = include_directories('contrib')

contrib_lib = static_library(
  'contrib',
  contrib_sources,
  include_directories: contrib_includes,
  dependencies: [libknot], # errcode.h
)

contrib = declare_dependency(
  include_directories: contrib_includes,
  link_with: contrib_lib,
)

## embedded lmdb (optional)

if not lmdb.found()
  sources = ['contrib/lmdb/mdb.c', 'contrib/lmdb/midl.c']
  includes = include_directories('contrib/lmdb')
  lib = static_library('lmdb', sources, include_directories: includes)
  lmdb = declare_dependency(link_with: lib, include_directories: includes)
endif

### libkres

libkres_sources = [
  'lib/cache/api.c',
  'lib/cache/cdb_lmdb.c',
  'lib/cache/entry_list.c',
  'lib/cache/entry_pkt.c',
  'lib/cache/entry_rr.c',
  'lib/cache/knot_pkt.c',
  'lib/cache/nsec1.c',
  'lib/cache/nsec3.c',
  'lib/cache/peek.c',
  'lib/dnssec.c',
  'lib/dnssec/nsec.c',
  'lib/dnssec/nsec3.c',
  'lib/dnssec/signature.c',
  'lib/dnssec/ta.c',
  'lib/generic/lru.c',
  'lib/generic/map.c',
  'lib/generic/trie.c',
  'lib/layer/cache.c',
  'lib/layer/iterate.c',
  'lib/layer/validate.c',
  'lib/module.c',
  'lib/nsrep.c',
  'lib/resolve.c',
  'lib/rplan.c',
  'lib/utils.c',
  'lib/zonecut.c',
]

libkres_headers = [
  'lib/cache/api.h',
  'lib/cache/cdb_api.h',
  'lib/cache/cdb_lmdb.h',
  'lib/cache/impl.h',
  'lib/defines.h',
  'lib/dnssec.h',
  'lib/dnssec/nsec.h',
  'lib/dnssec/nsec3.h',
  'lib/dnssec/signature.h',
  'lib/dnssec/ta.h',
  'lib/generic/array.h',
  'lib/generic/lru.h',
  'lib/generic/map.h',
  'lib/generic/pack.h',
  'lib/generic/trie.h',
  'lib/layer.h',
  'lib/layer/iterate.h',
  'lib/module.h',
  'lib/nsrep.h',
  'lib/resolve.h',
  'lib/rplan.h',
  'lib/utils.h',
  'lib/zonecut.h',
]

libkres_deps = [
  contrib, libuv, lua, lmdb, libknot, libdnssec, gnutls
]

if get_option('cookies')
  libkres_sources += [
    'lib/cookies/alg_containers.c',
    'lib/cookies/alg_containers.h',
    'lib/cookies/alg_sha.c',
    'lib/cookies/alg_sha.h',
    'lib/cookies/control.h',
    'lib/cookies/helper.c',
    'lib/cookies/helper.h',
    'lib/cookies/lru_cache.c',
    'lib/cookies/lru_cache.h',
    'lib/cookies/nonce.c',
    'lib/cookies/nonce.h',
  ]
  libkres_deps += [nettle]
endif

libkres_includes = include_directories('lib')

libkres_lib = library('kres',
  libkres_sources,
  include_directories: [libkres_includes],
  soversion: libkres_soversion,
  dependencies: libkres_deps,
  install: true,
)

libkres = declare_dependency(
  link_with: libkres_lib,
  include_directories: libkres_includes,
)

install_headers(
  libkres_headers,
  subdir: 'libkres',
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
  name: 'libkres',
  description: 'Knot Resolver library',
  url: 'https://knot-resolver.cz/',
  libraries: [libkres],
)

## kresc

kresc_sources = [
  'client/kresc.c',
]

kresc = executable(
  'kresc',
  kresc_sources,
  include_directories: include_directories('client'),
  dependencies: [contrib, libkres, libedit],
  install: true,
  install_dir: 'sbin',
)

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
  preserve_path_from: meson.current_source_dir(),
)

kresd_sources = [
  'daemon/bindings.c',
  'daemon/engine.c',
  'daemon/ffimodule.c',
  'daemon/io.c',
  'daemon/main.c',
  'daemon/network.c',
  'daemon/tls.c',
  'daemon/tls_ephemeral_credentials.c',
  'daemon/tls_session_ticket-srv.c',
  'daemon/worker.c',
  'daemon/zimport.c',
]

lib_suffix = '.so'
if build_machine.system() == 'darwin'
  lib_suffix = '.dylib'
endif

kresd = executable(
  'kresd',
  kresd_sources, kresd_lua,
  include_directories: include_directories('daemon'),
  c_args: [
    '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
    '-DPREFIX="@0@"'.format(get_option('prefix')),
    '-DMODULEDIR="@0@"'.format(modules_dir),
    '-DROOTHINTS="@0@/root.hints"'.format(get_option('sysconfdir')),
    '-DLIBEXT="@0@"'.format(lib_suffix),
    '-Dlibzscanner_SONAME="TODO.so"',
    '-Dlibknot_SONAME="TODO.so"',
    '-DLUA_HAS_SETFUNCS=1',
  ],
  dependencies: [contrib, libkres, libknot, libzscanner, libdnssec, libuv, lua, gnutls],
  install: true,
  install_dir: 'sbin',
)

## modules


library(
  'bogus_log',
  ['modules/bogus_log/bogus_log.c'],
  dependencies: [contrib, libkres, libknot, lua, libuv],
  install: true,
  install_dir: modules_dir,
  name_prefix: '',
)

#library(
#  'hints',
#  ['modules/hints/hints.c'],
#  dependencies: [contrib, libkres, lua],
#  install: true,
#  install_dir: modules_dir,
#  name_prefix: '',
#)

library(
  'stats',
  ['modules/stats/stats.c'],
  dependencies: [contrib, libkres, lua],
  install: true,
  install_dir: modules_dir,
  name_prefix: '',
)

# TODO: cookies
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
# todo...
