# daemon: lua modules

config_tests += [
  ['ta', files('trust_anchors.test/ta.test.lua')],
  ['ta_bootstrap', files('trust_anchors.test/bootstrap.test.lua')],
]

lua_config = configuration_data()
lua_config.set('keyfile_default', keyfile_default)
lua_config.set('etc_dir', etc_dir)
lua_config.set('unmanaged', managed_ta ? 'false' : 'true')

trust_anchors = configure_file(
  input: 'trust_anchors.lua.in',
  output: 'trust_anchors.lua',
  configuration: lua_config,
)

sandbox = configure_file(
  input: 'sandbox.lua.in',
  output: 'sandbox.lua',
  configuration: lua_config,
)

run_target(  # run manually to re-generate kres-gen.lua
  'kres-gen',
  command: find_program('./kres-gen.sh'),
)

lua_src = [
  files('config.lua'),
  files('kres.lua'),
  files('kres-gen.lua'),
  sandbox,
  trust_anchors,
  files('zonefile.lua'),
  files('kluautil.lua'),
]

# install daemon lua sources
install_data(
  lua_src,
  install_dir: lib_dir,
)
