# daemon: lua modules
# SPDX-License-Identifier: GPL-3.0-or-later

config_tests += [
  ['controlsock', files('controlsock.test.lua')],
  ['krprint', files('krprint.test.lua')],
  ['ta', files('trust_anchors.test/ta.test.lua')],
  ['ta_bootstrap', files('trust_anchors.test/bootstrap.test.lua'), ['y2k38']],
]

integr_tests += [
  ['map', meson.current_source_dir() / 'map.test.integr'],
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

## A simple config test: check that sizes of some Knot structures match
## in C and pre-generated lua bindings.
## The point is that regeneration is quite expensive in time and dependencies,
## but this basic sanity check could be ran always.
types_to_check = {
  'zs_scanner_t' : '#include <libzscanner/scanner.h>',
  'knot_pkt_t' : '#include <libknot/packet/pkt.h>',
}
# Construct the config test as a meson string.
kres_gen_test = '''
  local ffi = require('ffi')
  -- Test size of a C type
  local function tsoct(tname, csize)
    same(ffi.sizeof(ffi.typeof(tname)), csize,
      'C type `' .. tname .. '` has size: ' .. tostring(csize))
  end
  return { function ()
'''
foreach tname, tinclude: types_to_check
  kres_gen_test += '    tsoct("@0@", @1@)\n'.format(
    tname, meson.get_compiler('c').sizeof(tname, prefix : tinclude)
  )
endforeach
kres_gen_test += '''
  end }
'''
# Now convert it to a file (not very nice).
kres_gen_test_target = custom_target(
  'kres-gen.test.lua',
  output : ['kres-gen.test.lua'],
  command : ['echo', kres_gen_test],
  capture : true,
)
# Unfortunately, kres_gen_test_target.full_path() only works for meson >= 0.54,
# so we pass path and the dependency separately.
kres_gen_test_path = meson.build_root() / 'daemon' / 'lua' / 'kres-gen.test.lua'
config_tests += [
  ['kres_gen_test', [kres_gen_test_path], [], kres_gen_test_target],
]


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
