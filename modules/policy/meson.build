# lua-aho-corasick build
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
