# C module: nsid
# SPDX-License-Identifier: GPL-3.0-or-later

nsid_src = files([
  'nsid.c',
])
c_src_lint += nsid_src

nsid_mod = shared_module(
  'nsid',
  nsid_src,
  dependencies: mod_deps,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
  link_with: kresd,
)

config_tests += [
  ['nsid', files('nsid.test.lua')],
]
