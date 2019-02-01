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
  run_configtest = find_program('../../scripts/test-config.sh')
  foreach config_test : config_tests
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
      run_configtest,
      args: conftest_args,
      env: [
	'KRESD_NO_LISTEN=1',
	'SOURCE_PATH=@0@'.format(meson.current_source_dir()),
	'TEST_FILE=@0@/@1@'.format(meson.source_root(), config_test[1][0]),
	'KRESD_EXEC=@0@'.format(kresd_install_path),
      ],
      suite: [
	'config',
	'postinstall',
      ],
      should_fail: conftest_should_fail,
    )
  endforeach
endif
