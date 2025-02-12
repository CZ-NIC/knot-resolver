# SPDX-License-Identifier: GPL-3.0-or-later
# C module: tunnel_filter

tunnel_filter_src = files([
  'tunnel_filter.c',
])
c_src_lint += tunnel_filter_src

if libtorch.found()
  libtorch_dep = declare_dependency(
    link_args: ['-ltorch', '-ltorch_cpu'],
    dependencies: [libtorch]
  )


  blcnn_lib = static_library('blcnn',
    sources: ['libblcnn.cpp'],
    dependencies: [libtorch_dep]
  )


  tunnel_filter_mod = shared_module(
    'tunnel_filter',
    tunnel_filter_src,
    dependencies: mod_deps + [
      libtorch_dep
    ],
    include_directories: mod_inc_dir,
    name_prefix: '',
    install: true,
    install_dir: modules_dir,
    link_with: [blcnn_lib, kresd],
    link_args: ['-lstdc++', '-lc10']
  )
endif
