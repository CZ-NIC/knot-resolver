# C module: bogus_log

bogus_log_src = [
  'bogus_log.c',
]

bogus_log_mod = shared_module(
  'bogus_log',
  bogus_log_src,
  dependencies: [
    contrib_dep,
    libkres_dep,
    libknot,
  ],
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
