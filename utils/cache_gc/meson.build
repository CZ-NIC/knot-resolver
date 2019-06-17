## utils/cache_gc

cache_gc_src = files([
  'categories.c',
  'db.c',
  'kr_cache_gc.c',
  'main.c',
])

cache_gc = executable(
  'kres_cache_gc',
  cache_gc_src,
  dependencies: [
    contrib_dep,
    libkres_dep,
    libknot,
    luajit_inc,
  ],
  install: true,
  install_dir: get_option('sbindir'),
)
