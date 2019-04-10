# LUA module: experimental_dot_auth

lua_mod_src += [
  files('experimental_dot_auth.lua'),
]

# install static files
install_subdir(
  'static',
  strip_directory: true,
  install_dir: join_paths(modules_dir, 'http'),
)
