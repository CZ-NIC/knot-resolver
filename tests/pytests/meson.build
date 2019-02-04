tlsproxy_src = [
  'proxy/tlsproxy.c',
  'proxy/tls-proxy.c',
]

tlsproxy = executable(
  'tlsproxy',
  tlsproxy_src,
  dependencies: [
    libkres_dep,
    libuv,
    gnutls,
  ],
  build_by_default: false,
)


pytest = find_program('pytest', required: false)

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
  env: [
    'KRESD_EXEC=@0@'.format(kresd_install_path),
    'TLSPROXY_EXEC=@0@'.format(join_paths(meson.current_build_dir(), 'tlsproxy')),
  ],
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
  env: [
    'KRESD_EXEC=@0@'.format(kresd_install_path),
  ],
  suite: [
    'postinstall',
    'pytests',
  ],
  is_parallel: false,
  timeout: 240,
)
