# SPDX-License-Identifier: GPL-3.0-or-later
# C module: refuse_nord

integr_tests += [
  ['refuse_nord', meson.current_source_dir() / 'test.integr'],
]

refuse_nord_src = files([
  'refuse_nord.c',
])
c_src_lint += refuse_nord_src

refuse_nord_mod = shared_module(
  'refuse_nord',
  refuse_nord_src,
  dependencies: libknot,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
