# tests: pytests

tlsproxy_src = [
  'proxy/tlsproxy.c',
  'proxy/tls-proxy.c',
]

# compile tlsproxy
tlsproxy = executable(
  'tlsproxy',
  tlsproxy_src,
  dependencies: [
    libkres_dep,
    libuv,
    gnutls,
  ],
  c_args: c_args,
)

# python 3 dependencies
py3_deps += [
  ['jinja2', 'jinja2 (for pytests)'],
  ['dns', 'dnspython (for pytests)'],
  ['pytest', 'pytest (for pytests)'],
  ['pytest_html', 'pytest-html (for pytests)'],
  ['xdist', 'pytest-xdist (for pytests)'],
]

pytests_env = environment()
pytests_env.prepend('PATH', sbin_dir)
pytests_env.prepend('PATH', meson.current_build_dir())  # for tlsproxy

test(
  'pytests.basic',
  python3,
  args: [
    '-m', 'pytest',
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
  python3,
  args: [
    '-m', 'pytest',
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
