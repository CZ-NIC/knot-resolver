kresc_src = files([
    'main.c',
])
c_src_lint += kresc_src

if enable_sysrepo
    kresc = executable(
    'kresc',
    kresc_src,
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