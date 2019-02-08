# systemd

## paths
# TODO user mode
systemd_cache_dir = join_paths(
  prefix, get_option('localstatedir'), 'cache', 'knot-resolver')
run_dir = join_paths('/run', 'knot-resolver')
systemd_unit_dir = join_paths(prefix, get_option('libdir'), 'systemd', 'system')
systemd_tmpfiles_dir = join_paths(prefix, get_option('libdir'), 'tmpfiles.d')

## configuration
systemd_config = configuration_data()
systemd_config.set('user', user)
systemd_config.set('group', group)
systemd_config.set('systemd_cache_dir', systemd_cache_dir)
systemd_config.set('sbin_dir', sbin_dir)
systemd_config.set('etc_dir', etc_dir)
systemd_config.set('run_dir', run_dir)

# TODO Restart=on-abnormal

if systemd_socket
  ## unit files
  kresd_service = configure_file(
    input: 'kresd@.service.in',
    output: 'kresd@.service',
    configuration: systemd_config,
    install_dir: systemd_unit_dir,
  )
  kresd_control_socket = configure_file(
    input: 'kresd-control@.socket.in',
    output: 'kresd-control@.socket',
    configuration: systemd_config,
    install_dir: systemd_unit_dir,
  )
  install_data(
    sources: [
      'kresd.socket',
      'kresd-tls.socket',
      'kresd.target',
    ],
    install_dir: systemd_unit_dir,
  )

  ## man page
  kresd_systemd_man = configure_file(
    input: 'kresd.systemd.7.in',
    output: 'kresd.systemd.7',
    configuration: man_config,
  )
  install_man(kresd_systemd_man)

  ## tmpfiles
  tmpfiles = configure_file(
    input: 'tmpfiles.d/knot-resolver.conf.in',
    output: 'knot-resolver.conf',
    configuration: systemd_config,
    install_dir: systemd_tmpfiles_dir,
  )

  # TODO example drop-ins
else
  subdir('nosocket')
endif
