# SPDX-License-Identifier: GPL-3.0-or-later
# C module: stats

stats_src = files([
  'stats.c',
])
c_src_lint += stats_src

integr_tests += [
  ['stats', meson.current_source_dir() / 'test.integr'],
]


stats_mod = shared_module(
  'stats',
  stats_src,
  dependencies: [
    luajit_inc,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
