kres_watcher_src = files([
    'main.c',
    'watcher.c',
    'sdbus_client.c',
    'sysrepo_client.c',
])
c_src_lint += kres_watcher_src


if build_sysrepo
    kres_watcher = executable(
    'kres-watcher',
    kres_watcher_src,
    sysrepo_common_src,
    dependencies: [
      contrib_dep,
      libkres_dep,
      libyang,
      libsysrepo,
      libsystemd,
      libknot,
      luajit_inc,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif