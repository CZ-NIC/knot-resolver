# modules
# SPDX-License-Identifier: GPL-3.0-or-later

lua_mod_src = [  # add lua modules without separate meson.build
  files('detect_time_jump/detect_time_jump.lua'),
  files('detect_time_skew/detect_time_skew.lua'),
  files('dns64/dns64.lua'),
  files('etcd/etcd.lua'),
  files('graphite/graphite.lua'),
  files('predict/predict.lua'),
  files('prefill/prefill.lua'),
  files('priming/priming.lua'),
  files('rebinding/rebinding.lua'),
  files('renumber/renumber.lua'),
  files('serve_stale/serve_stale.lua'),
  files('ta_sentinel/ta_sentinel.lua'),
  files('ta_signal_query/ta_signal_query.lua'),
  files('watchdog/watchdog.lua'),
  files('workarounds/workarounds.lua'),
]

# When adding tests, prefer to use module's meson.build (if it exists).
config_tests += [
  ['predict', files('predict/predict.test.lua')],
  ['dns64', files('dns64/dns64.test.lua')],
  ['prefill', files('prefill/prefill.test/prefill.test.lua')],
]

integr_tests += [
  ['rebinding', meson.current_source_dir() / 'rebinding' / 'test.integr'],
  ['serve_stale', meson.current_source_dir() / 'serve_stale' / 'test.integr'],
  # NOTE: ta_update may pass in cases when it should fail due to race conditions
  # To ensure reliability, deckard should introduce a time wait
]


# handle more complex C/LUA modules separately
subdir('bogus_log')
# cookies module is not currently used
subdir('daf')
subdir('dnstap')
subdir('edns_keepalive')
subdir('experimental_dot_auth')
subdir('hints')
subdir('http')
subdir('nsid')
subdir('policy')
subdir('refuse_nord')
subdir('stats')
subdir('ta_update')
subdir('view')

# install lua modules
foreach mod : lua_mod_src
  install_data(
    mod,
    install_dir: modules_dir,
  )
endforeach
