# etc

example_configs = [
  'config.cluster',
  'config.docker',
  'config.isp',
  'config.personal',
  'config.splitview',
]

etc_files = [
  'icann-ca.pem',
  'root.hints',
]


install_data(
  sources: example_configs,
  install_dir: join_paths(doc_dir, 'examples'),
)

install_data(
  sources: etc_files,
  install_dir: etc_dir
)
