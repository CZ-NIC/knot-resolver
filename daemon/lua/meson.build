lua_modules_daemon = [
  'kres',
  'kres-gen',
  'trust_anchors',
  'zonefile',
]


# trust_anchors.lua
configure_file(
  input: 'trust_anchors.lua.in',
  output: 'trust_anchors.lua',
  configuration: config
)


# install lua modules
foreach mod : lua_modules_daemon
  install_data(
    join_paths(mod + '.lua'),
    install_dir: modules_dir,
  )
endforeach


if get_option('daemon')
  # dependencies for embedding lua
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
