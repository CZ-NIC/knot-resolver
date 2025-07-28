# python
# SPDX-License-Identifier: GPL-3.0-or-later

constants_config = configuration_data()
constants_config.set('version', meson.project_version())
constants_config.set('user', user)
constants_config.set('group', group)
constants_config.set('run_dir', run_dir)
constants_config.set('etc_dir', etc_dir)
constants_config.set('sbin_dir', sbin_dir)
constants_config.set('cache_dir', systemd_cache_dir)
constants_config.set('work_dir', systemd_work_dir)

configure_file(
  input: 'constants.py.in',
  output: 'constants.py',
  configuration: constants_config,
)
