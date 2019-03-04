config_tests += [
  ['basic', files('basic.test.lua'), [], false, ['skip_asan']],
  ['cache', files('cache.test.lua'), [], false, ['skip_asan']],
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

  # additional suites
  extra_suites = config_test.length() >= 5 ? config_test[4] : []

  # environment variables for test
  conftest_env = environment()
  conftest_env.prepend('PATH', sbin_dir)
  conftest_env.set('KRESD_NO_LISTEN', '1')
  conftest_env.set('SOURCE_PATH', meson.current_source_dir())
  conftest_env.set(
    'TEST_FILE', '@0@/@1@'.format(meson.source_root(), config_test[1][0]))

  test(
    'config.' + config_test[0],
    run_configtest,
    args: conftest_args,
    env: conftest_env,
    suite: [
      'postinstall',
      'config',
    ] + extra_suites,
    should_fail: conftest_should_fail,
  )
endforeach
