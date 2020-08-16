# systemd
# SPDX-License-Identifier: GPL-3.0-or-later

## configuration
systemd_config = configuration_data()
systemd_config.set('user', user)
systemd_config.set('group', group)
systemd_config.set('systemd_work_dir', systemd_work_dir)
systemd_config.set('systemd_cache_dir', systemd_cache_dir)
systemd_config.set('sbin_dir', sbin_dir)
systemd_config.set('etc_dir', etc_dir)
systemd_config.set('run_dir', run_dir)
systemd_config.set('lib_dir', lib_dir)

if systemd_files == 'enabled'
  ## unit files
  kresd_service = configure_file(
    input: 'kresd@.service.in',
    output: 'kresd@.service',
    configuration: systemd_config,
    install_dir: systemd_unit_dir,
  )
  kres_cache_gc_service = configure_file(
    input: 'kres-cache-gc.service.in',
    output: 'kres-cache-gc.service',
    configuration: systemd_config,
    install_dir: systemd_unit_dir,
  )
  install_data(
    sources: 'kresd.target',
    install_dir: systemd_unit_dir,
  )

  ## man page
  kresd_systemd_man = configure_file(
    input: 'kresd.systemd.7.in',
    output: 'kresd.systemd.7',
    configuration: man_config,
  )
  install_man(kresd_systemd_man)

  if libsystemd.version().version_compare('>=235')
    ## install tmpfiles for distributions with older systemd versions
    ## ignoring {Runtime,State,Cache}Directory=
    tmpfiles = configure_file(
      input: 'tmpfiles.d/knot-resolver.conf.in',
      output: 'knot-resolver.conf',
      configuration: systemd_config,
      install_dir: systemd_tmpfiles_dir,
    )
  endif
endif
