# kres-watcher: lua modules

sandbox_watcher = configure_file(
  input: 'sandbox-watcher.lua.in',
  output: 'sandbox-watcher.lua',
  configuration: lua_config,
)

lua_watcher_src = [
  sandbox_watcher,
  files('config-watcher.lua'),
]

# install daemon lua sources
install_data(
  lua_watcher_src,
  install_dir: lib_dir,
)