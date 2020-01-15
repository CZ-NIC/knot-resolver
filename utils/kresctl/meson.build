kresctl_src = files([
    'main.c',
])
c_src_lint += kresctl_src

if build_sysrepo
    kresc = executable(
    'kresctl',
    kresctl_src,
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