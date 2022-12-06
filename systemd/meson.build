# systemd
# SPDX-License-Identifier: GPL-3.0-or-later

## configuration
systemd_config = configuration_data()
systemd_config.set('user', user)
systemd_config.set('group', group)
systemd_config.set('systemd_work_dir', systemd_work_dir)
systemd_config.set('systemd_cache_dir', systemd_cache_dir)
systemd_config.set('sbin_dir', sbin_dir)
systemd_config.set('bin_dir', bin_dir)
systemd_config.set('etc_dir', etc_dir)
systemd_config.set('run_dir', run_dir)
systemd_config.set('lib_dir', lib_dir)

if systemd_legacy_units == 'enabled'

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

endif


if systemd_files == 'enabled'

  manager_service = configure_file(
    input: 'knot-resolver.service.in',
    output: 'knot-resolver.service',
    configuration: systemd_config,
    install_dir: systemd_unit_dir,
  )

  ## tmpfiles
  tmpfiles = configure_file(
    input: 'tmpfiles.d/knot-resolver.conf.in',
    output: 'knot-resolver.tmpfiles',
    configuration: systemd_config,
  )
  install_data(
    tmpfiles,
    rename: ['knot-resolver.conf'],
    install_dir: systemd_tmpfiles_dir,
  )

  ## sysusers
  sysusers = configure_file(
    input: 'sysusers.d/knot-resolver.conf.in',
    output: 'knot-resolver.sysusers',
    configuration: systemd_config,
  )
  install_data(
    sysusers,
    rename: ['knot-resolver.conf'],
    install_dir: systemd_sysusers_dir,
  )

  summary({'work_dir': systemd_work_dir,
           'cache_dir': systemd_cache_dir,
           'user': user,
           'group': group,
          }, section: 'Systemd')
endif
