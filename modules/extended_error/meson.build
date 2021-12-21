# C module: extended_error
# SPDX-License-Identifier: GPL-3.0-or-later

extended_error_src = files([
  'extended_error.c',
])
c_src_lint += extended_error_src

extended_error_mod = shared_module(
  'extended_error',
  extended_error_src,
  dependencies: [
    libknot,
    luajit_inc,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
