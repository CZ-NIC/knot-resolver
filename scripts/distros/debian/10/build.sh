meson build_packaging --default-library=static --prefix=/usr -Dwerror=true -Dextra_tests=enabled -Dsendmmsg=disabled
ninja -C build_packaging

