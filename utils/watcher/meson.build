watcher_src = files([
    'main.c',
])
c_src_lint += watcher_src

if build_sysrepo
  watcher = executable(
    'kres-watcher',
    watcher_src,
    sysrepo_common_src,
    dependencies: [
      libyang,
      libsysrepo,
      gnutls,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif
