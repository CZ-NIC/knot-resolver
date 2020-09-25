# etc: config examples
# SPDX-License-Identifier: GPL-3.0-or-later

# Install config examples
example_configs = [
  'config.cluster',
  'config.docker',
  'config.isp',
  'config.internal',
  'config.privacy',
  'config.personal',
  'config.splitview',
]

install_data(
  sources: example_configs,
  install_dir: examples_dir,
)


# kresd.conf
install_kresd_conf = get_option('install_kresd_conf') == 'enabled'
if get_option('install_kresd_conf') == 'auto'
  if run_command(['test', '-r', join_paths(etc_dir, 'kresd.conf')]).returncode() == 1
    install_kresd_conf = true
  endif
endif

if install_kresd_conf
  install_data(
    sources: 'config.personal',
    rename: 'kresd.conf',
    install_dir: etc_dir,
  )
endif
