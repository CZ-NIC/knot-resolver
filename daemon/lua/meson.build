# daemon: lua modules
# SPDX-License-Identifier: GPL-3.0-or-later

config_tests += [
  ['controlsock', files('controlsock.test.lua')],
  ['krprint', files('krprint.test.lua')],
  ['ta', files('trust_anchors.test/ta.test.lua')],
  ['ta_bootstrap', files('trust_anchors.test/bootstrap.test.lua')],
]

integr_tests += [
  ['map', join_paths(meson.current_source_dir(), 'map.test.integr')],
]

lua_config = configuration_data()
lua_config.set('keyfile_default', keyfile_default)
lua_config.set('etc_dir', etc_dir)
lua_config.set('run_dir', run_dir)
lua_config.set('systemd_cache_dir', systemd_cache_dir)
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

distro_preconfig = configure_file(
  input: 'distro-preconfig.lua.in',
  output: 'distro-preconfig.lua',
  configuration: lua_config,
)

run_target(  # run manually to re-generate kres-gen.lua
  'kres-gen',
  command: find_program('./kres-gen.sh'),
)

lua_src = [
  files('postconfig.lua'),
  files('kres.lua'),
  files('kres-gen.lua'),
  sandbox,
  trust_anchors,
  files('zonefile.lua'),
  files('kluautil.lua'),
  files('krprint.lua'),
  distro_preconfig,
]

# install daemon lua sources
install_data(
  lua_src,
  install_dir: lib_dir,
)
