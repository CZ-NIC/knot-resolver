# etc: config examples

# Config snippets (build-dependant)
if systemd_unit_files == 'enabled'
  config_defaults = '''
-- Network interface configuration: see kresd.systemd(7)'''
else
  config_defaults = '''
-- Listen on localhost (default) and external interface
-- net = { '127.0.0.1', '::1', '192.0.2.1' }

-- Drop root privileges
user('@0@', '@1@')'''.format(user, group)
endif


# Configure and install config examples
example_configs = [
  'config.cluster',
  'config.docker',
  'config.isp',
  'config.personal',
  'config.splitview',
]

conf_config = configuration_data()
conf_config.set('config_defaults', config_defaults)

foreach config_filename : example_configs
  configure_file(
    input: config_filename + '.in',
    output: config_filename,
    configuration: conf_config,
    install_dir: examples_dir,
  )
endforeach


# kresd.conf
install_kresd_conf = get_option('install_kresd_conf').enabled()
if get_option('install_kresd_conf').auto()
  if run_command(['test', '-r', join_paths(etc_dir, 'kresd.conf')]).returncode() == 1
    install_kresd_conf = true
  endif
endif

if install_kresd_conf
  configure_file(
    input: 'config.personal.in',
    output: 'kresd.conf',
    configuration: conf_config,
    install_dir: etc_dir,
  )
endif
