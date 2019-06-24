# C module: sd_watchdog

sd_watchdog_src = files([
  'sd_watchdog.c',
])
c_src_lint += sd_watchdog_src

sd_watchdog_mod = shared_module(
  'sd_watchdog',
  sd_watchdog_src,
  include_directories: mod_inc_dir,
  name_prefix: '',
  install: true,
  install_dir: modules_dir,
)
