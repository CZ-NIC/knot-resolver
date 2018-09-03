FROM fedora:29

WORKDIR "/tmp"
CMD ["/bin/bash"]

RUN dnf install -y mock rpkg git

# for scripts/make-distrofiles.sh
RUN dnf install -y dpkg-dev perl-Digest-*
