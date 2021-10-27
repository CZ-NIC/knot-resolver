# daemon: lua modules
# SPDX-License-Identifier: GPL-3.0-or-later

config_tests += [
  ['controlsock', files('controlsock.test.lua')],
  ['krprint', files('krprint.test.lua')],
  ['log', files('log.test.lua')],
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
                 ? 'kres-gen-31.lua' : 'kres-gen-30.lua')

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
# but this basic sanity check could be ran always, except for cross compilation,
# as we *run* luajit to find out the real sizes.
if get_option('kres_gen_test') and not meson.is_cross_build()
  types_to_check = [
    { 'tname': 'time_t', 'incl': '#include <sys/time.h>' },
    { 'tname': 'struct timeval', 'incl' : '#include <sys/time.h>' },
    { 'tname': 'zs_scanner_t', 'incl': '#include <libzscanner/scanner.h>', 'dep': libzscanner },
    { 'tname': 'knot_pkt_t', 'incl' : '#include <libknot/packet/pkt.h>', 'dep': libknot },
  ]
  # Construct the lua tester as a meson string.
  kres_gen_test_luastr = '''
    dofile('@0@')
    local ffi = require('ffi')
  '''.format(meson.current_source_dir() / kres_gen_fname)
  foreach ttc: types_to_check
    # We're careful with adding just includes; otherwise it's more fragile (e.g. linking flags).
    if 'dep' in ttc
      dep = ttc.get('dep').partial_dependency(includes: true, compile_args: true)
    else
      dep = []
    endif
    tsize = meson.get_compiler('c').sizeof(ttc.get('tname'), prefix: ttc.get('incl'),
                                           dependencies: dep)
    kres_gen_test_luastr += '''
      assert(ffi.sizeof(ffi.typeof('@0@')) == @1@,
        'Lua binding for C type ' .. '@0@' .. ' has incorrect size: '
        .. ffi.sizeof(ffi.typeof('@0@'))
      )
    '''.format(ttc.get('tname'), tsize)
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
