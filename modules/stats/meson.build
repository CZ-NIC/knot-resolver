# C module: stats

stats_src = files([
  'stats.c',
])
c_src_lint += stats_src

integr_tests += [
  ['stats', join_paths(meson.current_source_dir(), 'test.integr')],
]


stats_mod = shared_module(
  'stats',
  stats_src,
  dependencies: [
    contrib_dep,
    libknot,
  ],
  include_directories: luajit_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
