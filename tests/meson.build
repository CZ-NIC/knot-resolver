# tests

build_unit_tests = false
if not get_option('unit_tests').disabled()
  message('--- unit_tests dependencies ---')
  cmocka = dependency('cmocka', required: get_option('unit_tests'))
  if cmocka.found()
    build_unit_tests = true
    subdir('unit')
  endif
  message('-------------------------------')
endif

subdir('config')

build_extra_tests = get_option('extra_tests').enabled()  # NOTE 'auto' not supported
if build_extra_tests
  message('--- extra_tests dependencies ---')
  python3 = find_program('python3')
  py3_deps = []

  subdir('pytests')
  subdir('integration')

  foreach py3_dep : py3_deps
    py3_import = run_command(python3, '-c', 'import @0@'.format(py3_dep[0]))
    if py3_import.returncode() != 0
      message('missing python3 dependency: @0@'.format(py3_dep[1]))
    endif
  endforeach
  message('--------------------------------')
endif
