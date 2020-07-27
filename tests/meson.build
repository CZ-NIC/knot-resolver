# tests
# SPDX-License-Identifier: GPL-3.0-or-later

## unit tests
build_unit_tests = false
if get_option('unit_tests') != 'disabled'
  message('--- unit_tests dependencies ---')
  cmocka = dependency('cmocka', required: get_option('unit_tests') == 'enabled')
  if cmocka.found()
    build_unit_tests = true
    # subdir('unit')
  endif
  message('-------------------------------')
endif

build_extra_tests = get_option('extra_tests') == 'enabled'
build_config_tests = get_option('config_tests') == 'enabled'
if get_option('config_tests') == 'auto'
  build_config_tests = build_extra_tests
endif

## config tests
if build_config_tests
  message('--- config_tests dependencies ---')
  cqueues = run_command('luajit', '-l', 'cqueues', '-e', 'os.exit(0)')  # luajit -l $(1) -e "os.exit(0)"
  if cqueues.returncode() != 0
    error('missing luajit package: cqueues')
  endif
  message('---------------------------------')

  subdir('config')
endif

## extra tests
if build_extra_tests
  message('--- extra_tests dependencies ---')
  python3 = find_program('python3')
  py3_deps = []

  libuv_before_sendmmsg = dependency('libuv', version: '<1.35', required: false)
  subdir('pytests')
  if sendmmsg
    warning('Integration tests do not work with sendmmsg, disable sendmmsg using meson configure -Dsendmmsg=disabled builddir')
  elif not libuv_before_sendmmsg.found()
    warning('Integration tests do not work with libuv >= 1.35 because it internally uses sendmmsg which is not supported by Deckard, use an older version of libuv')
  else
    subdir('integration')
  endif

  foreach py3_dep : py3_deps
    py3_import = run_command(python3, '-c', 'import @0@'.format(py3_dep[0]))
    if py3_import.returncode() != 0
      error('missing python3 dependency: @0@'.format(py3_dep[1]))
    endif
  endforeach
  message('--------------------------------')
endif
