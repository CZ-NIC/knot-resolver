FROM debian:buster

RUN apt-get update && apt-get install -y systemd sudo

RUN useradd -m -s /bin/bash dev
RUN echo "dev:password" | chpasswd
RUN usermod -a -G sudo dev

CMD ["/sbin/init"]
