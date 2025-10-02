# C module: dns_tunnel_filter
# SPDX-License-Identifier: GPL-3.0-or-later


libtorch_dep = declare_dependency(
  link_args: ['-ltorch', '-ltorch_cpu'],
  dependencies: [libtorch]
)

blcnn_lib = static_library('blcnn',
  sources: ['libblcnn.cpp'],
  dependencies: [libtorch_dep]
)




dns_tunnel_filter_src = files([
  'dns_tunnel_filter.c',
])
c_src_lint += dns_tunnel_filter_src

dns_tunnel_filter_mod = shared_module(
  'dns_tunnel_filter',
  dns_tunnel_filter_src,
  dependencies: mod_deps,
  link_with: [kresd, blcnn_lib],
  link_args: ['-lstdc++', '-lc10'],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)

unit_tests += [
  #['dns_tunnel_filter', files('dns_tunnel_filter.test/tests.c') + libkres_src],
]
