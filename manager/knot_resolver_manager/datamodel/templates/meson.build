macros_dir = 'macros'
subdir(macros_dir)

py3.install_sources(
    files(
        'cache.lua.j2',
        'config.lua.j2',
        'dns64.lua.j2',
        'dnssec.lua.j2',
        'forward_zones.lua.j2',
        'logging.lua.j2',
        'monitoring.lua.j2',
        'network.lua.j2',
        'options.lua.j2',
        'policy.lua.j2',
        'rpz.lua.j2',
        'slices.lua.j2',
        'static_hints.lua.j2',
        'stub_zones.lua.j2',
        'views.lua.j2',
        'webmgmt.lua.j2',
    ),
    subdir: manager_module_dir / datamodel_dir / templates_dir
)