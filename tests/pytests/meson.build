tlsproxy_src = [
  'proxy/tlsproxy.c',
  'proxy/tls-proxy.c',
]

# compile tlsproxy
# TODO fix or silence compilation warnings
tlsproxy = executable(
  'tlsproxy',
  tlsproxy_src,
  dependencies: [
    libkres_dep,
    libuv,
    gnutls,
  ],
)

# pytests dependencies
pytest = find_program('pytest')

# python 3 dependencies
pytest_py3_deps = [
  ['jinja2', 'jinja2'],
  ['dnspython', 'dns'],
  ['pytest-html', 'pytest_html'],
  ['pytest-xdist', 'xdist'],
]
foreach py3_dep : pytest_py3_deps
  py3_import = run_command(python3, '-c', 'import @0@'.format(py3_dep[1]))
  if py3_import.returncode() != 0
    error('missing pytests dependency: python3 @0@'.format(py3_dep[0]))
  endif
endforeach

pytests_env = environment()
pytests_env.prepend('PATH', kresd_install_path)
pytests_env.prepend('PATH', meson.current_build_dir())  # for tlsproxy

test(
  'pytests.basic',
  pytest,
  args: [
    '--html', 'pytests.basic.html',
    '--self-contained-html',
    '-d',
    '-n', '24',
    meson.current_source_dir(),
  ],
  env: pytests_env,
  suite: [
    'postinstall',
    'pytests',
  ],
  is_parallel: false,
  timeout: 180,
  depends: tlsproxy,
)

test(
  'pytests.extended',
  pytest,
  args: [
    '-ra',
    '--capture=no',
    '@0@'.format(join_paths(meson.current_source_dir(), 'conn_flood.py')),
  ],
  env: pytests_env,
  suite: [
    'postinstall',
    'pytests',
  ],
  is_parallel: false,
  timeout: 240,
)
