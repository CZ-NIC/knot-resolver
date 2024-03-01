# python
# SPDX-License-Identifier: GPL-3.0-or-later

python_config = configuration_data()
python_config.set('kres_version', meson.project_version())
python_config.set('sbin_dir', sbin_dir)
python_config.set('bin_dir', bin_dir)
python_config.set('etc_dir', etc_dir)
python_config.set('run_dir', run_dir)
python_config.set('lib_dir', lib_dir)
python_config.set('modules_dir', modules_dir)

configure_file(
  input: 'knot_resolver.py.in',
  output: 'knot_resolver.py',
  configuration: python_config,
)

configure_file(
  input: 'setup.py.in',
  output: 'setup.py',
  configuration: python_config,
)
