FROM debian:latest

ENV LC_ALL=C.UTF-8

# install project dependencies

## build essentials
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y build-essential git ca-certificates

## python
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y python3 python3-pip python3-dev

## glib dependencies
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y libcairo2-dev libglib2.0-0 libgirepository1.0-dev

## python setuptools
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y python3-setuptools

## python libraries
RUN pip3 install aiohttp strictyaml pydbus PyGObject

## systemd
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y systemd

## kresd
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y wget
RUN wget https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb && dpkg -i knot-resolver-release.deb
RUN apt-get update && apt-get install -y knot-resolver

# dbus
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y dbus


# install test dependencies
RUN apt-get update && apt-get install --no-install-recommends --no-install-suggests -y curl

CMD ["/bin/systemd"]
