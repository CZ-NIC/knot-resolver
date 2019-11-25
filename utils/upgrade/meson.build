## utils/upgrade

upgrade_config = configuration_data()
upgrade_config.set('etc_dir', etc_dir)

configure_file(
  input: 'upgrade-4-to-5.lua.in',
  output: 'upgrade-4-to-5.lua',
  configuration: upgrade_config,
  install_dir: lib_dir
)
