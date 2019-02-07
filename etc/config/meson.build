# etc: config examples

# Config snippets (build-dependant)
if true  # TODO systemd.nosocket, systemd=no
  config_defaults = '''
-- Network interface configuration: see kresd.systemd(7)'''
else
  config_defaults = '''
-- Listen on localhost (default) and external interface
-- net = { '127.0.0.1', '::1', '192.0.2.1' }

-- Drop root privileges
user('knot-resolver', 'knot-resolver')'''  # TODO user, group
endif

if true  # TODO managed_ta = false
  config_managed_ta = '''
-- Auto-manage DNSSEC trust anchors (RFC 5011)
trust_anchors.file = '@0@/root.keys'
'''.format(etc_dir)
else
  config_managed_ta = ''
endif


example_configs = [
  'config.cluster.in',
  'config.docker.in',
  'config.isp.in',
  'config.personal.in',
  'config.splitview.in',
]

# TODO kresd.conf

# TODO configure, install
#install_data(
#  sources: example_configs,
#  install_dir: join_paths(doc_dir, 'examples'),
#)
