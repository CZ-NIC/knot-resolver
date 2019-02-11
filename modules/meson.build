# modules

lua_mod_src = [  # add lua modules without separate meson.build
  files('detect_time_jump/detect_time_jump.lua'),
  files('detect_time_skew/detect_time_skew.lua'),
  files('dns64/dns64.lua'),
  files('etcd/etcd.lua'),
  files('experimental_dot_auth/experimental_dot_auth.lua'),
  files('experimental_dot_auth/basexx.lua'),
  files('graphite/graphite.lua'),
  files('predict/predict.lua'),
  files('prefill/prefill.lua'),
  files('priming/priming.lua'),
  files('rebinding/rebinding.lua'),
  files('renumber/renumber.lua'),
  files('serve_stale/serve_stale.lua'),
  files('ta_sentinel/ta_sentinel.lua'),
  files('ta_signal_query/ta_signal_query.lua'),
  files('workarounds/workarounds.lua'),
]

config_tests += [
  ['predict', files('predict/predict.test.lua')],
  ['hints', files('hints/tests/hints.test.lua')],
  ['nsid', files('nsid/nsid.test.lua')],
  ['dns64', files('dns64/dns64.test.lua')],
]


# handle more complex C/LUA modules separately
subdir('bogus_log')
# cookies module is not currently used
subdir('daf')
subdir('dnstap')
subdir('edns_keepalive')
subdir('hints')
subdir('http')
subdir('nsid')
subdir('policy')
subdir('stats')
subdir('view')


# install lua modules
foreach mod : lua_mod_src
  install_data(
    mod,
    install_dir: modules_dir,
  )
endforeach
