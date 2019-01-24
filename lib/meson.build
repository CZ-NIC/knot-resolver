libkres_src = [
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
  'generic/map.c',
  'generic/queue.c',
  'generic/trie.c',
  'layer/cache.c',
  'layer/iterate.c',
  'layer/validate.c',
  'module.c',
  'nsrep.c',
  'resolve.c',
  'rplan.c',
  'utils.c',
  'zonecut.c',
]

libkres_headers = [
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
  'generic/map.h',
  'generic/pack.h',
  'generic/queue.h',
  'generic/trie.h',
  'layer.h',
  'layer/iterate.h',
  'module.h',
  'nsrep.h',
  'resolve.h',
  'rplan.h',
  'utils.h',
  'zonecut.h',
]

libkres_inc = include_directories('..')

libkres_lib = library('kres',
  libkres_src,
  soversion: libkres_soversion,
  include_directories: libkres_inc,
  dependencies: [
    contrib_dep,
    libuv,
    luajit,
    lmdb,
    libknot,
    libdnssec,
    gnutls,
  ],
  install: true,
)

libkres_dep = declare_dependency(
  include_directories: libkres_inc,
  link_with: libkres_lib
)

# TODO what dir structure does it create?
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
