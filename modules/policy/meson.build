# LUA module: policy
# SPDX-License-Identifier: GPL-3.0-or-later

lua_mod_src += [
  files('policy.lua'),
]

config_tests += [
  ['policy', files('policy.test.lua')],
  ['policy.slice', files('policy.slice.test.lua')],
  ['policy.rpz', files('policy.rpz.test.lua')],
]

integr_tests += [
  ['policy', meson.current_source_dir() / 'test.integr'],
  ['policy.noipv6', meson.current_source_dir() / 'noipv6.test.integr'],
  ['policy.noipvx', meson.current_source_dir() / 'noipvx.test.integr'],
]

# check git submodules were initialized
lua_ac_submodule = run_command(['test', '-r',
  '@0@/lua-aho-corasick/ac_fast.cxx'.format(meson.current_source_dir())])
if lua_ac_submodule.returncode() != 0
  error('run "git submodule update --init --recursive" to initialize git submodules')
endif

# compile bundled lua-aho-corasick as shared module
lua_ac_src = files([
  'lua-aho-corasick/ac_fast.cxx',
  'lua-aho-corasick/ac_lua.cxx',
  'lua-aho-corasick/ac_slow.cxx',
])

lua_ac_lib = shared_module(
  'ahocorasick',
  lua_ac_src,
  cpp_args: [
    '-fvisibility=hidden',
    '-Wall',
    '-fPIC',
  ],
  dependencies: [
    luajit_inc,
  ],
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: lib_dir,
)
