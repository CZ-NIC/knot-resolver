# systemd

## paths
systemd_work_dir = join_paths(
  prefix, get_option('localstatedir'), 'cache', 'knot-resolver')
run_dir = join_paths('/run', 'knot-resolver')
systemd_unit_dir = pkgconf_systemd.get_pkgconfig_variable('systemdsystemunitdir')
systemd_tmpfiles_dir = pkgconf_systemd.get_pkgconfig_variable('tmpfilesdir')

## configuration
systemd_config = configuration_data()
systemd_config.set('user', user)
systemd_config.set('group', group)
systemd_config.set('systemd_work_dir', systemd_work_dir)
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

  ## example drop-ins
  install_data(
    sources: [
      'kresd.socket.d/all-interfaces.conf',
      'kresd.socket.d/specific-interfaces.conf',
    ],
    install_dir: join_paths(examples_dir, 'kresd.socket.d'),
  )
  install_data(
    sources: [
      'kresd-tls.socket.d/all-interfaces.conf',
      'kresd-tls.socket.d/specific-interfaces.conf',
    ],
    install_dir: join_paths(examples_dir, 'kresd-tls.socket.d'),
  )
else
  subdir('nosocket')
endif
