# C module: stats

stats_src = [
  'stats.c',
]

stats_mod = shared_module(
  'stats',
  stats_src,
  dependencies: [
    contrib_dep,
    libkres_dep,
    libknot,
    luajit,
  ],
  name_prefix: '',
  c_args: c_args,
  install: true,
  install_dir: modules_dir,
)
