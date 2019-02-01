config_tests += [
  ['http.tls', files('test_tls/tls.test.lua')],
]

# install static files
install_subdir(
  'static',
  strip_directory: true,
  install_dir: join_paths(modules_dir, 'http'),
)
