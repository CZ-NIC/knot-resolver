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
    libkres_dep,
    libknot,
    luajit,
  ],
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
