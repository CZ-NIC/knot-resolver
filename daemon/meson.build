# SPDX-License-Identifier: GPL-3.0-or-later
# daemon

kresd_src = files([
  'bindings/cache.c',
  'bindings/event.c',
  'bindings/impl.c',
  'bindings/modules.c',
  'bindings/net.c',
  'bindings/worker.c',
  'defer.c',
  'engine.c',
  'ffimodule.c',
  'io.c',
  'main.c',
  'network.c',
  'proxyv2.c',
  'ratelimiting.c',
  'session2.c',
  'tls.c',
  'tls_ephemeral_credentials.c',
  'tls_session_ticket-srv.c',
  'udp_queue.c',
  'worker.c',
  'zimport.c',
  'quic_common.c',
  'quic_demux.c',
  'quic_conn.c',
  'quic_stream.c',
  # 'quic.c',
])

if nghttp2.found()
  kresd_src += files(['http.c'])
endif

c_src_lint += kresd_src

unit_tests += [
  ['ratelimiting', files('ratelimiting.test/tests.c') + libkres_src ],

  # parallel tests timeouts under valgrind; they checks mainly for race conditions, which is not needed there
  ['ratelimiting-parallel', files('ratelimiting.test/tests-parallel.c') + libkres_src, ['skip_valgrind']]
]

config_tests += [
  ['cache.clear', files('cache.test/clear.test.lua')],
  ['zimport', files('zimport.test/zimport.test.lua')],
]

integr_tests += [
  ['cache_insert_ns', meson.current_source_dir() / 'cache.test' / 'insert_ns.test.integr'],
  ['proxyv2', meson.current_source_dir() / 'proxyv2.test']
]

kresd_deps = [
  contrib_dep,
  kresconfig_dep,
  libkres_dep,
  libknot,
  libzscanner,
  libdnssec,
  libuv,
  luajit,
  gnutls,
  libsystemd,
  capng,
  nghttp2,
  malloc,
  libm,
  libngtcp2,
  libngtcp2_crypto,
]


subdir('lua')


kresd = executable(
  'kresd',
  kresd_src,
  dependencies: kresd_deps,
  export_dynamic: true,
  install: true,
  install_dir: get_option('sbindir'),
  install_rpath: rpath,
)
