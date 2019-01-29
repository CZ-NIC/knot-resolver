bogus_log_src = [
  'bogus_log.c',
]

bogus_log_mod = library(
  'bogus_log',
  bogus_log_src,
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
