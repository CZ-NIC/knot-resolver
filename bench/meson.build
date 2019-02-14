# bench

bench_lru_src = [
  'bench_lru.c',
]

cc = meson.get_compiler('c')
m_dep = cc.find_library('m', required : false)

bench_lru = executable(
  'bench_lru',
  bench_lru_src,
  dependencies: [
    contrib_dep,
    libkres_dep,
    m_dep,
  ],
)

run_target(
  'bench',
  command: '../scripts/bench.sh',
)
