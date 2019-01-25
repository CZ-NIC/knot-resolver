kresd_sources = [
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
  '-fPIE',  # TODO pie=true since 0.49.0
  '-DROOTHINTS="@0@/root.hints"'.format(
      join_paths(get_option('prefix'), get_option('sysconfdir'))),
  '-DLIBEXT="@0@"'.format(lib_suffix),
  '-Dlibzscanner_SONAME="@0@"'.format(libzscanner.get_pkgconfig_variable('soname')),
  '-Dlibknot_SONAME="@0@"'.format(libknot.get_pkgconfig_variable('soname')),
  '-DLUA_HAS_SETFUNCS=@0@'.format(luajit_has_setfuncs),
]

if host_machine.system() == 'darwin'
  # luajit workaround for OS X  https://luajit.org/install.html#embed
  c_args += ['-pagezero_size', '10000', '-image_base', '100000000']
endif


# daemon dependencies
skip_daemon = false

luajit = dependency('luajit', required: false)
if not luajit.found()
  skip_daemon = true
  message('kresd daemon: luajit not found')
endif

xxd = find_program('xxd', required: false)
if not xxd.found()
  hexdump = find_program('hexdump', required: false)
  if not hexdump.found()
    skip_daemon = true
    message('kresd daemon: neither xxd nor hexdump found')
  endif
endif


# optional dependencies

## systemd socket activation
libsystemd = dependency('libsystemd', version: '>=227', required: false)
if libsystemd.found()
  c_args += ['-DHAS_SYSTEMD']
endif


subdir('lua')


# build
if skip_daemon
  warning('kresd daemon: skipping build')
else
  kresd = executable(
    'kresd',
    kresd_sources, kresd_lua,
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
    c_args: c_args,
    install: true,
    install_dir: 'sbin',
  )
endif
