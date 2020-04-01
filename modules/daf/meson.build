# LUA module: daf
# SPDX-License-Identifier: GPL-3.0-or-later

config_tests += [
  ['daf', files('daf.test.lua')],
  ['daf_http', files('daf_http.test.lua')],
]

lua_mod_src += [
  files('daf.lua'),
]

# install daf.js
install_data(
  'daf.js',
  install_dir: join_paths(modules_dir, 'daf'),
)
