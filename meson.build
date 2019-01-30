project(
  'knot-resolver',
  ['c', 'cpp'],
  license: 'GPLv3+',
  version: '3.2.1',  # TODO dev version from git
  default_options: ['c_std=c99'],  # TODO why not c11?
)

libkres_soversion = 9

if get_option('modules_dir') == ''
  modules_dir = join_paths(
    get_option('prefix'), get_option('libdir'), 'knot-resolver')
else
  modules_dir = get_option('modules_dir')
endif
message('modules_dir: ' + modules_dir)

config = configuration_data()
config.set('keyfile_default', get_option('keyfile_default'))
config.set('etc_dir',
  join_paths(get_option('prefix'), get_option('sysconfdir'), 'knot-resolver'))

# Project-wide dependencies

knot_version = '>=2.7.6'
libknot = dependency('libknot', version: knot_version)
libdnssec = dependency('libdnssec', version: knot_version)
libzscanner = dependency('libzscanner', version: knot_version)
libuv = dependency('libuv', version: '>=1.7')
lmdb = dependency('lmdb')
gnutls = dependency('gnutls')
luajit = dependency('luajit')


# Optional dependencies

## documentation
doxygen = find_program('doxygen', required: false)
sphinx_build = find_program('sphinx-build', required: false)
python_breathe = run_command(
  'python3', ['-c', 'import breathe']).returncode() == 0
if not python_breathe
  warning('python: breathe not found')
endif

## tests
cmocka = dependency('cmocka', required: false)
socket_wrapper = dependency('socket_wrapper', required: false)

## coverage
lcov = find_program('lcov', required: false)
luacov = find_program('luacov', required: false)


# Variables

# TODO @DATE@. @VERSION@, ...

add_global_arguments(
  '-D_GNU_SOURCE',
  '-Wtype-limits',
  '-Wformat',
  '-Wformat-security',
  '-Wshadow',
  '-Wall',
  '-DPACKAGE_VERSION="@0@"'.format(meson.project_version()),
  '-DPREFIX="@0@"'.format(get_option('prefix')),
  '-DMODULEDIR="@0@"'.format(modules_dir),
  '-fvisibility=hidden',
  language: 'c',
)


subdir('contrib')
subdir('lib')
subdir('client')
subdir('daemon')
subdir('modules')

# TODO install man

# install

# etc

install_data(sources: 'etc/root.hints', install_dir: config.get('etc_dir'))
