# SPDX-License-Identifier: GPL-3.0-or-later
# daemon

kresd_src = files([
  'bindings/cache.c',
  'bindings/event.c',
  'bindings/impl.c',
  'bindings/modules.c',
  'bindings/net.c',
  'bindings/worker.c',
  'engine.c',
  'ffimodule.c',
  'http.c',
  'io.c',
  'main.c',
  'network.c',
  'session.c',
  'tls.c',
  'tls_ephemeral_credentials.c',
  'tls_session_ticket-srv.c',
  'http.c',
  'udp_queue.c',
  'worker.c',
  'zimport.c',
])
c_src_lint += kresd_src

config_tests += [
  ['cache.clear', files('cache.test/clear.test.lua')],
]

integr_tests += [
  ['cache_insert_ns', join_paths(meson.current_source_dir(), 'cache.test', 'insert_ns.test.integr')]
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
]


subdir('lua')


kresd = executable(
  'kresd',
  kresd_src,
  dependencies: kresd_deps,
  export_dynamic: true,
  install: true,
  install_dir: get_option('sbindir'),
)
