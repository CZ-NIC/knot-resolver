FROM fedora:29

WORKDIR "/tmp"
CMD ["/bin/bash"]

RUN dnf install -y mock rpkg git

# for scripts/make-distrofiles.sh
RUN dnf install -y dpkg-dev perl-Digest-*

# add OBS repo with Knot DNS to mock
RUN curl -Lo obs-epel7.repo 'https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-latest/CentOS_7_EPEL/home:CZ-NIC:knot-resolver-latest.repo'
RUN sed -i -e "/^config_opts\[.yum.conf.]/r obs-epel7.repo" /etc/mock/epel-7-x86_64.cfg

# cache packages in mock to speed up CI tests
# This would require privileged build: https://github.com/moby/moby/issues/1916
# RUN dnf download --source knot-resolver
# RUN mock --no-clean --dnf --old-chroot -r epel-7-x86_64 --rebuild knot-resolver-*.src.rpm
# RUN mock --no-clean --old-chroot -r fedora-29-x86_64 --rebuild knot-resolver-*.src.rpm
# RUN rm *.src.rpm
# RUN mock --no-clean --old-chroot -r fedora-29-x86_64 --rebuild knot-resolver-*.src.rpm
# RUN rm *.src.rpm
