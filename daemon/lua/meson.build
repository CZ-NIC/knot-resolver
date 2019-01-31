lua_src_daemon = [
  'kres.lua',
  'kres-gen.lua',
  # trust_anchors.lua.in handled separately
  'zonefile.lua',
]

config_tests += [
  # TODO bootstrap
]

# install lua modules
foreach mod : lua_src_daemon
  install_data(
    mod,
    install_dir: modules_dir,
  )
endforeach

configure_file(
  input: 'trust_anchors.lua.in',
  output: 'trust_anchors.lua',
  configuration: config,
  install_dir: modules_dir,
)


# embed lua to daemon
if get_option('daemon')
  # dependencies
  xxd = find_program('xxd', required: false)
  if not xxd.found()
    hexdump = find_program('hexdump')
  endif

  embed_lua = generator(
    find_program('../../scripts/embed-lua.sh'),
    arguments: ['@INPUT@'],
    output: '@BASENAME@.inc',
    capture: true,
  )

  kresd_lua = embed_lua.process(
    'sandbox.lua',
    'config.lua',
    preserve_path_from: meson.source_root(),
  )
endif
