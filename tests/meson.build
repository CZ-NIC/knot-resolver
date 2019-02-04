subdir('config')
subdir('unit')

if get_option('extra_tests')
  python3 = find_program('python3')
  py3_deps = []

  subdir('pytests')
  #subdir('integration')

  foreach py3_dep : py3_deps
    py3_import = run_command(python3, '-c', 'import @0@'.format(py3_dep[0]))
    if py3_import.returncode() != 0
      error('missing python3 dependency: @0@'.format(py3_dep[1]))
    endif
  endforeach

endif
