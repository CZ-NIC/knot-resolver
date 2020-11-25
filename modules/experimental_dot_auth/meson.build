# LUA module: experimental_dot_auth
# SPDX-License-Identifier: GPL-3.0-or-later

lua_mod_src += [
  files('experimental_dot_auth.lua'),
]

# install static files
install_subdir(
  'static',
  strip_directory: true,
  install_dir: modules_dir / 'http',
)
