# daemon

kresd_src = [
  'bindings/cache.c',
  'bindings/event.c',
  'bindings/impl.c',
  'bindings/modules.c',
  'bindings/net.c',
  'bindings/worker.c',
  'engine.c',
  'ffimodule.c',
  'io.c',
  'main.c',
  'network.c',
  'session.c',
  'tls.c',
  'tls_ephemeral_credentials.c',
  'tls_session_ticket-srv.c',
  'worker.c',
  'zimport.c',
]

config_tests += [
  ['cache.clear', files('cache.test/clear.test.lua')],
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
]

if systemd
  kresd_deps += libsystemd
endif


subdir('lua')


kresd = executable(
  'kresd',
  kresd_src,
  dependencies: kresd_deps,
  export_dynamic: true,
  install: true,
  install_dir: get_option('sbindir'),
)
