# tests: pytests
# SPDX-License-Identifier: GPL-3.0-or-later

# python 3 dependencies
py3_deps += [
  ['jinja2', 'jinja2 (for pytests)'],
  ['dns', 'dnspython (for pytests)'],
  ['pytest', 'pytest (for pytests)'],
  ['pytest_html', 'pytest-html (for pytests)'],
  ['xdist', 'pytest-xdist (for pytests)'],
]

if gnutls.version().version_compare('<3.6.4')
  error('pytests require GnuTLS >= 3.6.4')
endif

# compile tlsproxy
tlsproxy_src = files([
  'proxy/tlsproxy.c',
  'proxy/tls-proxy.c',
])
tlsproxy = executable(
  'tlsproxy',
  tlsproxy_src,
  dependencies: [
    libkres_dep,
    libuv,
    gnutls,
  ],
)

# path to kresd and tlsproxy
pytests_env = environment()
pytests_env.prepend('PATH', sbin_dir, meson.current_build_dir())

test(
  'pytests.parallel',
  python3,
  args: [
    '-m', 'pytest',
    '-d',
    '--html', 'pytests.parallel.html',
    '--self-contained-html',
    '-n', '24',
    '-v',
  ],
  env: pytests_env,
  suite: [
    'postinstall',
    'pytests',
  ],
  workdir: meson.current_source_dir(),
  is_parallel: false,
  timeout: 180,
  depends: tlsproxy,
)

test(
  'pytests.single',
  python3,
  args: [
    '-m', 'pytest',
    '-ra',
    '--capture=no',
    'conn_flood.py',
  ],
  env: pytests_env,
  suite: [
    'postinstall',
    'pytests',
  ],
  workdir: meson.current_source_dir(),
  is_parallel: false,
  timeout: 240,
)
