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
  is_parallel: false,
  timeout: 180,
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
  depends: tlsproxy,
)
