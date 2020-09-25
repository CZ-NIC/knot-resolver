# C module: bogus_log
# SPDX-License-Identifier: GPL-3.0-or-later

bogus_log_src = files([
  'bogus_log.c',
])
c_src_lint += bogus_log_src

bogus_log_mod = shared_module(
  'bogus_log',
  bogus_log_src,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
