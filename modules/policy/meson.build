# LUA module: policy

lua_src += [
  files('policy.lua'),
]

config_tests += [
  ['policy', files('policy.test.lua')],
]

integr_tests += [
  ['policy.noipv6', join_paths(meson.current_source_dir(), 'noipv6.test.integr')],
  ['policy.noipvx', join_paths(meson.current_source_dir(), 'noipvx.test.integr')],
]


# compile bundled lua-aho-corasick lib
lua_ac_src = [
  'lua-aho-corasick/ac_fast.cxx',
  'lua-aho-corasick/ac_lua.cxx',
  'lua-aho-corasick/ac_slow.cxx',
]

lua_ac_lib = library(
  'ahocorasick',
  lua_ac_src,
  dependencies: luajit,
  cpp_args: [
    '-O3',
    '-fvisibility=hidden',
    '-Wall',
    '-fPIC',
  ],
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
