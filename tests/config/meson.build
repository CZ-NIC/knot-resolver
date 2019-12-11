config_tests += [
  # NOTE _leaks: not sure what exactly is wrong in leak detection on config tests
  # NOTE skip_asan: all three of these disappear locally when using gcc 9.1 (except some leaks)
  ['basic', files('basic.test.lua'), ['skip_asan']],
  ['cache', files('cache.test.lua'), ['skip_asan']],
  ['net', files('net.test.lua'), ['config_net']],  # requires privileged docker
  ['lru', files('lru.test.lua')],
  ['tls', files('tls.test.lua')],
  ['worker', files('worker.test.lua')],
]


run_configtest = find_program('../../scripts/test-config.sh')


foreach config_test : config_tests
  # additional suites
  extra_suites = config_test.length() >= 3 ? config_test[2] : []

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
    args: [
	'-c', files('test.cfg'),
	'-f', '1',
    ],
    env: conftest_env,
    suite: [
      'postinstall',
      'config',
    ] + extra_suites,
  )
endforeach
