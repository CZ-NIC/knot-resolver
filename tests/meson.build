# Unit tests
unit_tests = [
  'test_array',
  #'test_cache',  # TODO: re-consider how best to test cache
  'test_lru',
  'test_map',
  'test_module',
  'test_pack',
  'test_queue',
  'test_rplan',
  'test_set',
  'test_trie',
  'test_utils',
  'test_zonecut',
]

# dependency
cmocka = dependency('cmocka', required: false)

if cmocka.found()

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
      unit_test,
      unit_test + '.c',
      dependencies: [
	contrib_dep,
	libkres_dep,
	cmocka,
	lmdb,
      ],
    )
    test(
      unit_test,
      exec_test,
      suite: 'unit',
    )
  endforeach
endif
