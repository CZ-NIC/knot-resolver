# C module: hints

hints_src = [
  'hints.c',
]

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
