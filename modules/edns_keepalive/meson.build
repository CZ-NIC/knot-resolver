# C module: edns_keepalive

edns_keepalive_src = files([
  'edns_keepalive.c',
])
c_src_lint += edns_keepalive_src

edns_keepalive_mod = shared_module(
  'edns_keepalive',
  edns_keepalive_src,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
