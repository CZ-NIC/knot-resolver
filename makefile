install:
	rm -rf build
	rm -rf /tmp/kr
	meson build -Db_sanitize=address --prefix=/tmp/kr --default-library=static
	ninja -C build
	ninja install -C build

shm_clean:
	make -C /home/jetconf/kres-sysrepo/sysrepo/build shm_clean