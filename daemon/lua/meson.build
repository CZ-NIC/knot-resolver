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

# Unfortunately the different ABI implies different contents of 'kres-gen.lua'.
kres_gen_fname = (libknot.version().version_compare('>= 3.1')
                 ? 'kres-gen-31.lua' : 'kres-gen-29.lua')

kres_gen_lua = configure_file(
  input: kres_gen_fname,
  output: 'kres-gen.lua',
  copy: true,
)

run_target(  # run manually to re-generate kres-gen.lua
  'kres-gen',
  command: [ find_program('./kres-gen.sh'), kres_gen_fname ],
)

# A simple config test: check that sizes of some structures match
# in C and pre-generated lua bindings.
# The point is that regeneration is quite expensive in time and dependencies,
# but this basic sanity check could be ran always.
if get_option('kres_gen_test')
  types_to_check = {
	'time_t' : '#include <sys/time.h>',
	'struct timeval' : '#include <sys/time.h>',
	'zs_scanner_t' : '#include <libzscanner/scanner.h>',
	'knot_pkt_t' : '#include <libknot/packet/pkt.h>',
  }
  # Construct the lua tester as a meson string.
  kres_gen_test_luastr = '''
	dofile('@0@')
	local ffi = require('ffi')
  '''.format(meson.current_source_dir() / kres_gen_fname)
  foreach tname, tinclude: types_to_check
	kres_gen_test_luastr += '''
	  assert(ffi.sizeof(ffi.typeof('@0@')) == @1@,
		'Lua binding for C type ' .. '@0@' .. ' has incorrect size: '
		.. ffi.sizeof(ffi.typeof('@0@'))
	  )
	'''.format(tname, meson.get_compiler('c').sizeof(tname, prefix : tinclude))
  endforeach
  # Now feed it directly into luajit.
  kres_gen_test = run_command(find_program('luajit'), '-e', kres_gen_test_luastr)
  if kres_gen_test.returncode() != 0
	error('if you use released Knot* versions, please contact us: https://www.knot-resolver.cz/contact/\n'
		+ kres_gen_test.stderr().strip())
  endif
endif

# A simple config test: check that sizes of some structures match
# in C and pre-generated lua bindings.
# The point is that regeneration is quite expensive in time and dependencies,
# but this basic sanity check could be ran always.
if get_option('kres_gen_test')
  types_to_check = {
	'time_t' : '#include <sys/time.h>',
	'struct timeval' : '#include <sys/time.h>',
	'zs_scanner_t' : '#include <libzscanner/scanner.h>',
	'knot_pkt_t' : '#include <libknot/packet/pkt.h>',
  }
  # Construct the lua tester as a meson string.
  kres_gen_test_luastr = '''
	dofile('@0@')
	local ffi = require('ffi')
  '''.format(meson.current_source_dir() / 'kres-gen.lua')
  foreach tname, tinclude: types_to_check
	kres_gen_test_luastr += '''
	  assert(ffi.sizeof(ffi.typeof('@0@')) == @1@,
		'Lua binding for C type ' .. '@0@' .. ' has incorrect size: '
		.. ffi.sizeof(ffi.typeof('@0@'))
	  )
	'''.format(tname, meson.get_compiler('c').sizeof(tname, prefix : tinclude))
  endforeach
  # Now feed it directly into luajit.
  kres_gen_test = run_command(find_program('luajit'), '-e', kres_gen_test_luastr)
  if kres_gen_test.returncode() != 0
	error('if you use released Knot* versions, please contact us: https://www.knot-resolver.cz/contact/\n'
		+ kres_gen_test.stderr().strip())
  endif
endif

lua_src = [
  files('postconfig.lua'),
  files('kres.lua'),
  kres_gen_lua,
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
