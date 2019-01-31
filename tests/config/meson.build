config_tests += [
  ['basic', files('basic.test.lua')],
  ['cache', files('cache.test.lua')],
  ['keyfile.bad_args', files('keyfile/bad_args.test.lua'),
    ['--keyfile-ro', 'root.keys',
     '--keyfile', 'root.keys'],
    true,
  ],
  ['keyfile.load_ta', files('keyfile/load_ta.test.lua'),
    ['--keyfile-ro', files('keyfile/root2.keys')]
  ],
  ['keyfile.nonexist1', files('keyfile/nonexist1.test.lua'),
    ['--keyfile-ro', 'nonexist'],
    true,
  ],
  ['keyfile.nonexist2', files('keyfile/nonexist2.test.lua'),
    ['--keyfile-ro', 'nonexist'],
    true,
  ],
  ['lru', files('lru.test.lua')],
  ['tls', files('tls.test.lua')],
  ['worker', files('worker.test.lua')],
]


if get_option('daemon')
  foreach config_test : config_tests
    conftest_dir = join_paths(meson.current_build_dir(), config_test[0])

    testdir_clean = custom_target(
      'config.' + config_test[0] + ': clean testdir',
      command: [
	'rm', '-r', '-f', conftest_dir,
      ],
      output: config_test[0] + '.rm',
      build_by_default: false,
    )

    testdir_create = custom_target(
      'config.' + config_test[0] + ': create testdir',
      command: [
	'mkdir', conftest_dir,
      ],
      depends: testdir_clean,
      output: config_test[0],
      build_always_stale: true,  # make sure to always recreate dir
      build_by_default: false,
    )

    # kresd arguments
    conftest_args = [
      '-c', files('test.cfg'),
      '-f', '1',
    ]
    if config_test.length() >= 3
      conftest_args += config_test[2]
    endif

    # kresd return code check
    conftest_should_fail = config_test.length() >= 4 ? config_test[3] : false

    test(
      'config.' + config_test[0],
      kresd,
      args: conftest_args,
      env: [
	'KRESD_NO_LISTEN=1',
	'SOURCE_PATH=@0@'.format(meson.current_source_dir()),
	'TEST_FILE=@0@/@1@'.format(meson.source_root(), config_test[1][0]),
      ],
      suite: 'config',
      workdir: join_paths(meson.current_build_dir(), config_test[0]),
      depends: testdir_create,
      should_fail: conftest_should_fail,
    )
  endforeach
endif
