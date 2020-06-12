install:
	rm -rf build
	rm -rf /tmp/kr
	meson build --prefix=/tmp/kr --default-library=static
	ninja -C build
	ninja install -C build
	sudo chmod -R 777 /tmp/kr/

shm_clean:
	sudo make -C /home/jetconf/kres-sysrepo/sysrepo/build shm_clean