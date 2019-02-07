# daemon: lua modules + embed

ta_config = configuration_data()
ta_config.set('keyfile_default', keyfile_default)
ta_config.set('etc_dir', etc_dir)
trust_anchors = configure_file(
  input: 'trust_anchors.lua.in',
  output: 'trust_anchors.lua',
  configuration: ta_config,
)

lua_src += [
  files('kres.lua'),
  files('kres-gen.lua'),
  trust_anchors,
  files('zonefile.lua'),
]

config_tests += [
  ['ta_bootstrap', files('trust_anchors.test/bootstrap.test.lua')],
]


# daemon dependencies
build_daemon = false
if not get_option('daemon').disabled()
  message('--- daemon dependencies ---')
  xxd = find_program('xxd', required: false)
  if xxd.found()
    build_daemon = true
  else
    # fallback
    hexdump = find_program('hexdump', required: get_option('daemon'))
    if hexdump.found()
      build_daemon = true
    endif
  endif
  embed_lua = find_program('../../scripts/embed-lua.sh')
  message('--------------------------------------')
endif

# embed lua to daemon
if build_daemon
  embed_lua = generator(
    embed_lua,
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
