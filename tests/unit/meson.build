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
  dependencies: libknot,
  include_directories: mod_inc_dir,
)

# executables with tests
foreach unit_test : unit_tests
  exec_test = executable(
    unit_test[0],
    unit_test[1],
    dependencies: [
      contrib_dep,
      libkres_dep,
      libknot,
      cmocka,
      lmdb,
    ],
  )
  test(
    'unit.' + unit_test[0],
    exec_test,
    suite: 'unit',
    # they take very short time
    kwargs: meson.version().version_compare('<0.52') ? {} : { 'priority': -5 },
  )
endforeach
