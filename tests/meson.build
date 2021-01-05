# tests
# SPDX-License-Identifier: GPL-3.0-or-later

## unit tests
build_unit_tests = false
if get_option('unit_tests') != 'disabled'
  message('--- unit_tests dependencies ---')
  cmocka = dependency('cmocka', required: get_option('unit_tests') == 'enabled')
  if cmocka.found()
    build_unit_tests = true
    subdir('unit')
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
  basexx = run_command('luajit', '-l', 'basexx', '-e', 'os.exit(0)')  # luajit -l $(1) -e "os.exit(0)"
  if basexx.returncode() != 0
    error('missing luajit package: basexx')
  endif
  ffi = run_command('luajit', '-l', 'ffi', '-e', 'os.exit(0)')  # luajit -l $(1) -e "os.exit(0)"
  if ffi.returncode() != 0
    error('missing luajit package: ffi')
  endif
  message('---------------------------------')

  subdir('config')
endif

## dnstap tests
if build_dnstap
  test('dnstap',
    find_program('./dnstap/src/dnstap-test/run.sh'),
    args: [ sbin_dir / 'kresd' ],
    suite: [ 'postinstall', 'config' ],
    timeout: 120, # it may need to fetch go packages, etc.
  )
endif

## extra tests
if build_extra_tests
  message('--- extra_tests dependencies ---')
  python3 = find_program('python3')
  py3_deps = []

  subdir('pytests')
  subdir('integration')

  foreach py3_dep : py3_deps
    py3_import = run_command(python3, '-c', 'import @0@'.format(py3_dep[0]))
    if py3_import.returncode() != 0
      error('missing python3 dependency: @0@'.format(py3_dep[1]))
    endif
  endforeach
  message('--------------------------------')
endif
