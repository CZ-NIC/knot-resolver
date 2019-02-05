# LUA module: http

lua_src += [
  files('http.lua'),
  files('http_trace.lua'),
  files('prometheus.lua'),
]

config_tests += [
  ['http', files('http.test.lua')],
  ['http.tls', files('test_tls/tls.test.lua')],
]

# install static files
install_subdir(
  'static',
  strip_directory: true,
  install_dir: join_paths(modules_dir, 'http'),
)
