# C module: dga_filter
# SPDX-License-Identifier: GPL-3.0-or-later

dga_filter_src = files([
  'dga_filter.c',
  'model_features.c',
])

dga_filter_mod = shared_module(
  'dga_filter',
  dga_filter_src,
  dependencies: mod_deps + [
    libpsl
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
  link_with: kresd,
)

unit_tests += [
  #['dga_filter', files('dga_filter.test/tests.c') + libkres_src],
]
