## utils/cache_gc
# SPDX-License-Identifier: GPL-3.0-or-later

cache_gc_src = files([
  'categories.c',
  'db.c',
  'kr_cache_gc.c',
  'main.c',
])
if build_sysrepo
  cache_gc_src += sysrepo_common_src
endif

c_src_lint += cache_gc_src

if build_utils
  cache_gc = executable(
    'kres-cache-gc',
    cache_gc_src,
    dependencies: [
      kresconfig_dep,
      contrib_dep,
      libkres_dep,
      libyang,
      libsysrepo,
      libknot,
      luajit_inc,
    ],
    install: true,
    install_dir: get_option('sbindir'),
  )
endif
