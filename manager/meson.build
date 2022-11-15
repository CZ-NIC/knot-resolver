# SPDX-License-Identifier: GPL-3.0-or-later

build_manager = false

if get_option('manager') != 'disabled'
    message('--- manager dependencies ---')

    pymod = import('python')
    py3 = pymod.find_installation('python3')
    py3_deps = run_command(py3, 'tests/packaging/dependencies.py', 'setup.py', check: false)

    if py3.language_version().version_compare('<3.6')
        error('At least Python 3.6 is required.')
    elif py3_deps.returncode() != 0
        error(py3_deps.stderr().strip())
    else
        message('all dependencies found')
        build_manager = true
    endif

    message('----------------------------')
endif

if build_manager

    # installation script
    meson.add_install_script('scripts/install.sh', py3.path())

    # YAML config configuration file
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