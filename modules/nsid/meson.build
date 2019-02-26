# C module: nsid

nsid_src = files([
  'nsid.c',
])
c_src_lint += nsid_src

nsid_mod = shared_module(
  'nsid',
  nsid_src,
  dependencies: [
    contrib_dep,
    libkres_dep,
    libknot,
    luajit,
  ],
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
