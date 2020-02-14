# tests: unit
# SPDX-License-Identifier: GPL-3.0-or-later

# mock module for test_module
mock_cmodule_src = files([
  'mock_cmodule.c',
])

mock_cmodule_mod = shared_module(
  'mock_cmodule',
  mock_cmodule_src,
  name_prefix: '',
  include_directories: include_directories('../../'),
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
