# SPDX-License-Identifier: GPL-3.0-or-later
# C module: dga_filter

filter_src = files([
  'dga_filter.c',
])
c_src_lint += filter_src

config_tests += [
  ['dga_filter', files('dga_filter.test.lua')],
]

if libonnxruntime.found() and libpsl.found()
  filter_mod = shared_module(
    'dga_filter',
    filter_src,
    dependencies: mod_deps + [
      libonnxruntime,
      libpsl
    ],
    include_directories: mod_inc_dir,
    name_prefix: '',
    install: true,
    install_dir: modules_dir,
    link_with: kresd,
  )
endif
