# lua-aho-corasick build
lua_ac_src = [
  'lua-aho-corasick/ac_fast.cxx',
  'lua-aho-corasick/ac_lua.cxx',
  'lua-aho-corasick/ac_slow.cxx',
]

lua_ac_lib = library(
  'ahocorasick',
  lua_ac_src,
  name_prefix: '',
  dependencies: luajit,
  install: true,
  install_dir: modules_dir,
  cpp_args: [
    '-O3',
    '-fvisibility=hidden',
    '-Wall',
    '-fPIC',
  ],
  link_args: [
    '-shared',
    #'-Wl,-soname=ahocorasick.so',  # TODO what does this do, is it needed?
  ],
)
