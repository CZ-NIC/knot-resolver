# C module: dga_filter
# SPDX-License-Identifier: GPL-3.0-or-later

cc = meson.get_compiler('c')

ort_lib = cc.find_library('onnxruntime', required: true)

ort_inc = include_directories('/usr/include/onnxruntime')

libonnxruntime = declare_dependency(
  dependencies: [ort_lib],
  include_directories: ort_inc
)

dga_filter_src = files([
  'dga_filter.c',
])
c_src_lint += dga_filter_src

dga_filter_mod = shared_module(
  'dga_filter',
  dga_filter_src,
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

unit_tests += [
  #['dga_filter', files('dga_filter.test/tests.c') + libkres_src],
]
