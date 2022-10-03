# manager
# SPDX-License-Identifier: GPL-3.0-or-later

build_manager = false
if get_option('manager') != 'disabled'
    message('--- manager dependencies ---')

    python3 = find_program('python3', version: '>=3.6')

    build_manager = true
    message('----------------------------')
endif

if build_manager
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