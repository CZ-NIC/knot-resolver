# tests: unit

# mock module for test_module
mock_cmodule_src = [
  'mock_cmodule.c',
]

mock_cmodule_lib = library(
  'mock_cmodule',
  mock_cmodule_src,
  name_prefix: '',
  dependencies: libkres_dep,
)

mock_cmodule_dep = declare_dependency(
  link_with: mock_cmodule_lib,
)

# executables with tests
foreach unit_test : unit_tests
  exec_test = executable(
    unit_test[0],
    unit_test[1],
    dependencies: [
      contrib_dep,
      libkres_dep,
      cmocka,
      lmdb,
    ],
  )
  test(
    'unit.' + unit_test[0],
    exec_test,
    suite: 'unit',
  )
endforeach
