# kres-watcher

watcher_src = files([
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
  'udp_queue.c',
  'watcher.c',
  'worker.c',
  'zimport.c',
  'sr_subscriptions.c',
  'dbus_control.c'
])
c_src_lint += watcher_src

watcher_deps = [
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
  libyang,
  libsysrepo,
]

subdir('lua')

if build_sysrepo
  kres_watcher = executable(
    'kres-watcher',
    watcher_src,
    sysrepo_common_src,
    dependencies: watcher_deps,
    export_dynamic: true,
    install: true,
    install_dir: get_option('sbindir'),
  )
endif
