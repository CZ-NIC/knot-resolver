edns_keepalive_src = [
  'edns_keepalive.c',
]

edns_keepalive_mod = library(
  'edns_keepalive',
  edns_keepalive_src,
  dependencies: [
    contrib_dep,
    libkres_dep,
    libknot,
  ],
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
