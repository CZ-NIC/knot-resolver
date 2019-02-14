# C module: stats

stats_src = [
  'stats.c',
]

integr_tests += [
  ['stats', join_paths(meson.current_source_dir(), 'test.integr')],
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
  install: true,
  install_dir: modules_dir,
)
