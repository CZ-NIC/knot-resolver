# manager
# SPDX-License-Identifier: GPL-3.0-or-later

build_manager = false
build_manager_client = false

if get_option('manager') != 'disabled'
    message('--- manager dependencies ---')

    python_deps = [
        # 'jinja2',
        # 'yaml',
        # 'aiohttp',
        # 'prometheus_client',
        # 'supervisor',
        # 'typing_extensions',
    ]

    pymod = import('python')
    py3 = pymod.find_installation('python3', modules: python_deps)
    py3_deps = py3.dependency()

    if py3.language_version().version_compare('<3.6')
        error('At least Python 3.6 is required.')
    else
        build_manager = true
    endif

    message('----------------------------')
elif get_option('manager') == 'disabled' and get_option('manager_client') == 'enabled'
    error('manager client cannot be build without manager')
endif

if build_manager

    manager_module_dir = 'knot_resolver_manager'
    subdir(manager_module_dir)

    # YAML config: etc/knot-resolver/config.yml
    install_data(
        sources: 'etc/knot-resolver/config.yml',
        install_dir: etc_dir,
    )

    # systemd service
    if systemd_files == 'enabled'
        install_data(
            sources: 'knot-resolver.service',
            install_dir: systemd_unit_dir,
        )
    endif
endif