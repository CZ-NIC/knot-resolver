lua_modules_daemon = [
  'kres',
  'kres-gen',
  #'trust_anchors',  # TODO
  'zonefile',
]

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
