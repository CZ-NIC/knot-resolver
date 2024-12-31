# SPDX-License-Identifier: GPL-3.0-or-later
# C module: filter

filter_src = files([
  'filter.c',
])
c_src_lint += filter_src

config_tests += [
  ['filter', files('filter.test.lua')],
]

if libidn2.found() and libpcre2.found()
  filter_mod = shared_module(
    'filter',
    filter_src,
    dependencies: mod_deps + [
      libidn2,
      libpcre2,
    ],
    include_directories: mod_inc_dir,
    name_prefix: '',
    install: true,
    install_dir: modules_dir,
    link_with: kresd,
  )
endif
