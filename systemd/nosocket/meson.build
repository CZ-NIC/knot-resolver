# systemd: nosocket

## unit files
kresd_service = configure_file(
  input: 'kresd@.service.in',
  output: 'kresd@.service',
  configuration: systemd_config,
  install_dir: systemd_unit_dir,
)

install_data(
  sources: 'kresd.target',
  install_dir: systemd_unit_dir,
)

install_man('kresd.systemd.nosocket.7')  # TODO amend man page + configure

# tmpfiles
tmpfiles = configure_file(
  input: 'tmpfiles.d/knot-resolver.conf.in',
  output: 'knot-resolver.conf',
  configuration: systemd_config,
  install_dir: systemd_tmpfiles_dir,
)
