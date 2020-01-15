kres_watcher_src = files([
    'main.c',
])
c_src_lint += kres_watcher_src

if enable_sysrepo
    kres_watcher = executable(
    'kres-watcher',
    kres_watcher_src,
    sysrepo_common_src,
    dependencies: [
      contrib_dep,
      libkres_dep,
      libyang,
      libsysrepo,
      libknot,
      luajit_inc,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif