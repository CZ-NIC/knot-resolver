# C module: hints

hints_src = files([
  'hints.c',
])
c_src_lint += hints_src

hints_mod = shared_module(
  'hints',
  hints_src,
  dependencies: [
    contrib_dep,
    libknot,
  ],
  include_directories: luajit_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
