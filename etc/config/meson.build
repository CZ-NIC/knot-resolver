# etc: config examples

# Config snippets (build-dependant)
if systemd_socket
  config_defaults = '''
-- Network interface configuration: see kresd.systemd(7)'''
else
  config_defaults = '''
-- Listen on localhost (default) and external interface
-- net = { '127.0.0.1', '::1', '192.0.2.1' }

-- Drop root privileges
user('@0@', '@1@')'''.format(user, group)
endif

if managed_ta
  config_managed_ta = '''
-- Auto-manage DNSSEC trust anchors (RFC 5011)
trust_anchors.file = '@0@/root.keys'
'''.format(etc_dir)
else
  config_managed_ta = ''
endif


# Configure and install config examples
example_configs = [
  'config.cluster',
  'config.docker',  # TODO should it be installed?
  'config.isp',
  'config.personal',
  'config.splitview',
]

conf_config = configuration_data()
conf_config.set('config_defaults', config_defaults)
conf_config.set('config_managed_ta', config_managed_ta)

examples_dir = join_paths(doc_dir, 'examples')

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
