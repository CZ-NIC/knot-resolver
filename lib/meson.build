# libkres
# SPDX-License-Identifier: GPL-3.0-or-later

libkres_src = files([
  'cache/api.c',
  'cache/cdb_lmdb.c',
  'cache/entry_list.c',
  'cache/entry_pkt.c',
  'cache/entry_rr.c',
  'cache/knot_pkt.c',
  'cache/nsec1.c',
  'cache/nsec3.c',
  'cache/peek.c',
  'dnssec.c',
  'dnssec/nsec.c',
  'dnssec/nsec3.c',
  'dnssec/signature.c',
  'dnssec/ta.c',
  'generic/lru.c',
  'generic/queue.c',
  'generic/trie.c',
  'kru-avx2.c',
  'kru-generic.c',
  'layer/cache.c',
  'layer/iterate.c',
  'layer/validate.c',
  'log.c',
  'mmapped.c',
  'proto.c',
  'rules/api.c',
  'rules/defaults.c',
  'rules/forward.c',
  'rules/local-addr.c',
  'rules/zonefile.c',
  'module.c',
  'resolve.c',
  'resolve-produce.c',
  'rplan.c',
  'selection.c',
  'selection_forward.c',
  'selection_iter.c',
  'sigsafe.c',
  'utils.c',
  'zonecut.c',
])
c_src_lint += libkres_src

libkres_headers = files([
  'cache/api.h',
  'cache/cdb_api.h',
  'cache/cdb_lmdb.h',
  'cache/impl.h',
  'defines.h',
  'dnssec.h',
  'dnssec/nsec.h',
  'dnssec/nsec3.h',
  'dnssec/signature.h',
  'dnssec/ta.h',
  'generic/array.h',
  'generic/lru.h',
  'generic/pack.h',
  'generic/queue.h',
  'generic/trie.h',
  'kru.h',
  'layer.h',
  'layer/iterate.h',
  'log.h',
  'mmapped.h',
  'module.h',
  'proto.h',
  'resolve.h',
  'resolve-impl.h',
  'rplan.h',
  'rules/api.h',
  'rules/impl.h',
  'selection.h',
  'selection_forward.h',
  'selection_iter.h',
  'sigsafe.h',
  'utils.h',
  'zonecut.h',
])

unit_tests += [
  ['array', files('generic/test_array.c')],
  ['lru', files('generic/test_lru.c')],
  ['pack', files('generic/test_pack.c')],
  ['queue', files('generic/test_queue.c')],
  ['trie', files('generic/test_trie.c')],
  ['module', files('test_module.c')],
  ['rplan', files('test_rplan.c')],
  ['utils', files('test_utils.c')],
  ['zonecut', files('test_zonecut.c')],
]

integr_tests += [
  ['cache_overflow', meson.current_source_dir() / 'cache' / 'overflow.test.integr'],
  ['cache_minimal_nsec', meson.current_source_dir() / 'cache' / 'test.integr'],
  ['iter_limits' , meson.current_source_dir() / 'layer' / 'test.integr'],
  ['validate' , meson.current_source_dir() / 'layer' / 'validate.test.integr'],
]

libkres_inc = include_directories('..')

libkres_lib = library('kres',
  libkres_src,
  soversion: libkres_soversion,
  include_directories: libkres_inc,
  dependencies: [
    contrib_dep,
    kresconfig_dep,
    libuv,
    lmdb,
    libknot,
    libzscanner,
    libdnssec,
    gnutls,
    luajit,
    libsystemd,
    libm
  ],
  install: true,
)

libkres_dep = declare_dependency(
  include_directories: libkres_inc,
  link_with: libkres_lib
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
  libraries: [libkres_lib],
)
