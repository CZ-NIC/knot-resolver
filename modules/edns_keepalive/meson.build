edns_keepalive_src = [
  'edns_keepalive.c',
]

edns_keepalive_mod = library(
  'edns_keepalive',
  edns_keepalive_src,
  name_prefix: '',
  dependencies: [
    contrib_dep,
    libkres_dep,
    libknot,
  ],
  link_args: link_args_c_mods,
  install: true,
  install_dir: modules_dir,
)
