# C module: padding

padding_src = files([
  'padding.c',
])
c_src_lint += padding_src

integr_tests += [
  ['padding', join_paths(meson.current_source_dir(), 'test.integr')],
]


padding_mod = shared_module(
  'padding',
  padding_src,
  dependencies: [
    luajit_inc,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
