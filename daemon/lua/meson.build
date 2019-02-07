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


# embed lua to daemon
if get_option('daemon')
  message('--- required kresd dependencies ---')
  xxd = find_program('xxd', required: false)
  if not xxd.found()
    hexdump = find_program('hexdump')
  endif
  embed_lua = find_program('../../scripts/embed-lua.sh')
  message('--------------------------------------')

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
