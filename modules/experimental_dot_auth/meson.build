# LUA module: experimental_dot_auth

lua_mod_src += [
  files('experimental_dot_auth.lua'),
]

# install bundled basexx dependency
install_data(
  files('basexx.lua'),
  install_dir: lib_dir,
)

# install static files
install_subdir(
  'static',
  strip_directory: true,
  install_dir: join_paths(modules_dir, 'http'),
)
