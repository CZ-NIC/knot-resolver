# C module: hints
# SPDX-License-Identifier: GPL-3.0-or-later

hints_src = files([
  'hints.c',
])
c_src_lint += hints_src

hints_mod = shared_module(
  'hints',
  hints_src,
  dependencies: [
    libknot,
    luajit_inc,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)

config_tests += [
  ['hints', files('tests/hints.test.lua'), ['skip_asan']],
]
