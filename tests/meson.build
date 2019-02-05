# tests

message('--- unit test dependencies ---')
cmocka = dependency('cmocka', required: false)
if cmocka.found()
  subdir('unit')
endif
message('------------------------------')

subdir('config')

if get_option('extra_tests')
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
