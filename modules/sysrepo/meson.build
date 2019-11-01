# C module: sysrepo

sysrepo_src = files([
  'sysrepo.c',
])
c_src_lint += sysrepo_src

sysrepo_mod = shared_module(
  'sysrepo',
  sysrepo_src,
  dependencies: [
    luajit_inc,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
