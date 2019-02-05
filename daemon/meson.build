# daemon

kresd_src = [
  'bindings.c',
  'engine.c',
  'ffimodule.c',
  'io.c',
  'main.c',
  'network.c',
  'session.c',
  'tls.c',
  'tls_ephemeral_credentials.c',
  'tls_session_ticket-srv.c',
  'worker.c',
  'zimport.c',
]

config_tests += [
  ['cache.clear', files('cache.test/clear.test.lua')],
]


lib_suffix = '.so'
# TODO seek&destroy LIBEXT
if host_machine.system() == 'darwin'
  lib_suffix = '.dylib'
endif

luajit_has_setfuncs = run_command(
  'pkg-config', ['luajit', '--atleast-version', '2.1.0-beta3']
  ).returncode() == 0 ? '1' : '0'

# daemon CFLAGS
c_args = [
  '-fPIE',  # NOTE this triggers warning, but is needed for compatibility with meson 0.47.0
  '-DROOTHINTS="@0@/root.hints"'.format(config.get('etc_dir')),
  '-DLIBEXT="@0@"'.format(lib_suffix),
  '-Dlibzscanner_SONAME="@0@"'.format(libzscanner.get_pkgconfig_variable('soname')),
  '-Dlibknot_SONAME="@0@"'.format(libknot.get_pkgconfig_variable('soname')),
  '-DLUA_HAS_SETFUNCS=@0@'.format(luajit_has_setfuncs),
]

# TODO test build on osx
if host_machine.system() == 'darwin'
  # luajit workaround for OS X  https://luajit.org/install.html#embed
  c_args += ['-pagezero_size', '10000', '-image_base', '100000000']
endif


# optional systemd socket activation
message('--- optional kresd dependencies ---')
libsystemd = dependency('libsystemd', version: '>=227', required: false)
if libsystemd.found()
  c_args += ['-DHAS_SYSTEMD']
  config.set('man_seealso_systemd', '\\fIkresd.systemd(7)\\fR, ')
endif
message('-----------------------------------')


subdir('lua')


if get_option('daemon')
  # build
  kresd = executable(
    'kresd',
    kresd_src, kresd_lua,
    dependencies: [
      contrib_dep,
      libkres_dep,
      libknot,
      libzscanner,
      libdnssec,
      libuv,
      luajit,
      gnutls,
      libsystemd,
    ],
    export_dynamic: true,
    c_args: c_args,
    install: true,
    install_dir: get_option('sbindir'),
  )

  kresd_install_path = join_paths(  # path used in tests
    get_option('prefix'), get_option('sbindir'))
endif
