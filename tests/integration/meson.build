# tests: integration (using deckard)
# SPDX-License-Identifier: GPL-3.0-or-later

# deckard dependencies
cmake = find_program('cmake')  # for libswrapper
git = find_program('git')
make = find_program('make')
augeas = dependency('augeas')

# python3 dependencies
py3_deps += [
  ['augeas', 'augeas (for deckard)'],
  ['dns', 'dnspuyhon (for deckard)'],
  ['jinja2', 'jinja2 (for deckard)'],
  ['pytest', 'pytest (for deckard)'],
  ['xdist', 'pytest-xdist (for deckard)'],
  ['yaml', 'PyYAML (for deckard)'],
]

prepare_deckard = find_program('../../scripts/test-integration-prepare.sh')

deckard_env = environment()
deckard_env.prepend('PATH', sbin_dir)

junitxml_prefix = '--junitxml=' + meson.build_root() + '/meson-logs'

deckard_kresd_run = find_program('deckard/kresd_run.sh')
test(
  'integration.deckard',
  deckard_kresd_run,
  env: deckard_env,
  args: [
    '-n', 'auto',
    '-Wignore::DeprecationWarning',
    junitxml_prefix + '/integration.deckard.junit.xml',
  ],
  suite: [
    'postinstall',
    'integration',
  ],
  is_parallel: false,
  timeout: 300,
)

deckard_run = find_program('deckard/run.sh')
foreach integr_test : integr_tests
  deckard_config_path = integr_test[1] / 'deckard.yaml'
  test(
    'integration.' + integr_test[0],
    deckard_run,
    env: deckard_env,
    args: [
      '-n', 'auto',
      '-Wignore::DeprecationWarning',
      '--config=@0@'.format(deckard_config_path),
      '--scenarios=@0@'.format(integr_test[1]),
      junitxml_prefix + '/integration.' + integr_test[0] + '.junit.xml',
    ],
    suite: [
      'postinstall',
      'integration',
    ],
    is_parallel: false,
    workdir: meson.source_root(),
  )
endforeach
