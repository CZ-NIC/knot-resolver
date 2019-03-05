%global _hardened_build 1
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}}

%define GPG_CHECK 0
%define VERSION __VERSION__
%define repodir %{_builddir}/%{name}-%{version}
%define NINJA ninja-build

Name:           knot-resolver
Version:        %{VERSION}
Release:        1%{?dist}
Summary:        Caching full DNS Resolver

License:        GPLv3
URL:            https://www.knot-resolver.cz/
Source0:        knot-resolver_%{version}.orig.tar.xz

# LuaJIT only on these arches
%if 0%{?rhel}
# RHEL 7 does not have aarch64 LuaJIT
ExclusiveArch:	%{ix86} x86_64
%else
ExclusiveArch:	%{arm} aarch64 %{ix86} x86_64
%endif

%if 0%{GPG_CHECK}
Source1:        knot-resolver-%{version}.tar.xz.asc
# PGP keys used to sign upstream releases
# Export with --armor using command from https://fedoraproject.org/wiki/PackagingDrafts:GPGSignatures
# Don't forget to update %%prep section when adding/removing keys
Source100:	gpgkey-B6006460B60A80E782062449E747DF1F9575A3AA.gpg.asc
Source101:	gpgkey-BE26EBB9CBE059B3910CA35BCE8DD6A1A50A21E4.gpg.asc
Source102:	gpgkey-4A8BA48C2AED933BD495C509A1FBA5F7EF8C4869.gpg.asc
BuildRequires:  gnupg2
%endif

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  meson
BuildRequires:  pkgconfig(cmocka)
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(libedit)
BuildRequires:  pkgconfig(libknot) >= 2.7.6
BuildRequires:  pkgconfig(libzscanner) >= 2.7.6
BuildRequires:  pkgconfig(libdnssec) >= 2.7.6
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(libuv)
BuildRequires:  pkgconfig(luajit) >= 2.0

Requires:	systemd

# Distro-dependent dependencies
%if 0%{?rhel}
BuildRequires:  lmdb-devel
# Lua 5.1 version of the libraries have different package names
Requires:       lua-socket
Requires:       lua-sec
Requires(pre):	shadow-utils
%endif
%if 0%{?fedora}
BuildRequires:  pkgconfig(lmdb)
BuildRequires:  python3-sphinx
Requires:       lua-socket-compat
Requires:       lua-sec-compat
Requires:       lua-cqueues-compat
Requires(pre):	shadow-utils
%endif
%if 0%{?suse_version}
%define NINJA ninja
BuildRequires:  lmdb-devel
BuildRequires:  python3-Sphinx
Requires:       lua51-luasocket
Requires:       lua51-luasec
Requires(pre):	shadow
%endif

%if "x%{?rhel}" == "x"
# dependencies for doc package
# enable once CentOS 7.6 makes it into OBS buildroot
BuildRequires:  doxygen
BuildRequires:  python3-breathe
BuildRequires:  python3-sphinx_rtd_theme
%endif

%description
The Knot Resolver is a DNSSEC-enabled caching full resolver implementation
written in C and LuaJIT, including both a resolver library and a daemon.
Modular architecture of the library keeps the core tiny and efficient, and
provides a state-machine like API for extensions.

The package is pre-configured as local caching resolver.
To start using it, start a single kresd instance:
$ systemctl start kresd@1.service

%package devel
Summary:        Development headers for Knot Resolver
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The package contains development headers for Knot Resolver.

%if "x%{?rhel}" == "x"
%package doc
Summary:        Documentation for Knot Resolver
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}

%description doc
Documentation for Knot Resolver
%endif

%prep
%if 0%{GPG_CHECK}
export GNUPGHOME=./gpg-keyring
mkdir ${GNUPGHOME}
gpg2 --import %{SOURCE100} %{SOURCE101} %{SOURCE102}
gpg2 --verify %{SOURCE1} %{SOURCE0}
%endif
%setup -q -n %{name}-%{version}

%build
CFLAGS="%{optflags}" LDFLAGS="%{?__global_ldflags}" meson build_rpm \
%if "x%{?rhel}" == "x"
    -Ddoc=enabled \
    -Dsystemd_files=enabled \
%else
    -Dsystemd_files=nosocket \
%endif
    -Dclient=enabled \
    -Dunit_tests=enabled \
    -Dmanaged_ta=enabled \
    -Dinstall_kresd_conf=enabled \
    --buildtype=plain \
    --prefix="%{_prefix}" \
    --sbindir="%{_sbindir}" \
    --libdir="%{_libdir}" \
    --includedir="%{_includedir}" \
    --sysconfdir="%{_sysconfdir}" \

%{NINJA} -v -C build_rpm
%if "x%{?rhel}" == "x"
%{NINJA} -v -C build_rpm doc
%endif

%check
meson test -C build_rpm

%install
DESTDIR="${RPM_BUILD_ROOT}" %{NINJA} -v -C build_rpm install

# add kresd.target to multi-user.target.wants to support enabling kresd services
install -m 0755 -d %{buildroot}%{_unitdir}/multi-user.target.wants
ln -s ../kresd.target %{buildroot}%{_unitdir}/multi-user.target.wants/kresd.target

# install .tmpfiles.d dirs
install -m 0750 -d %{buildroot}%{_localstatedir}/cache/%{name}
install -m 0750 -d %{buildroot}/run/%{name}

# remove modules with missing dependencies
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/etcd.lua
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/prefill.lua
rm -r %{buildroot}%{_libdir}/knot-resolver/kres_modules/http
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/http.lua
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/http_trace.lua
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/prometheus.lua

# rename doc directory for centos, opensuse
%if "x%{?fedora}" == "x"
install -m 755 -d %{buildroot}/%{_pkgdocdir}
mv %{buildroot}/%{_datadir}/doc/%{name}/* %{buildroot}/%{_pkgdocdir}/
%endif

%pre
getent group knot-resolver >/dev/null || groupadd -r knot-resolver
getent passwd knot-resolver >/dev/null || useradd -r -g knot-resolver -d %{_sysconfdir}/knot-resolver -s /sbin/nologin -c "Knot Resolver" knot-resolver

%post
%systemd_post 'kresd@*.service'
%if 0%{?fedora}
# https://fedoraproject.org/wiki/Changes/Removing_ldconfig_scriptlets
%else
/sbin/ldconfig
%endif

%preun
%systemd_preun 'kresd@*.service' kresd.target kresd.socket kresd-tls.socket

%postun
# NOTE: this doesn't restart the services on CentOS 7
%systemd_postun_with_restart 'kresd@*.service'
%if 0%{?fedora}
# https://fedoraproject.org/wiki/Changes/Removing_ldconfig_scriptlets
%else
/sbin/ldconfig
%endif

%files
%dir %{_pkgdocdir}
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/AUTHORS
%doc %{_pkgdocdir}/NEWS
%doc %{_pkgdocdir}/examples
%attr(775,root,knot-resolver) %dir %{_sysconfdir}/knot-resolver
%attr(644,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/kresd.conf
%attr(664,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/root.keys
%attr(644,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/root.hints
%attr(644,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/icann-ca.pem
%{_unitdir}/kresd*.service
%{_unitdir}/kresd.target
%dir %{_unitdir}/multi-user.target.wants
%{_unitdir}/multi-user.target.wants/kresd.target
%if "x%{?rhel}" == "x"
%{_unitdir}/kresd*.socket
%ghost /run/%{name}/
%{_mandir}/man7/kresd.systemd.7.gz
%else
%{_mandir}/man7/kresd.systemd.nosocket.7.gz
%endif
%{_tmpfilesdir}/knot-resolver.conf
%attr(750,knot-resolver,knot-resolver) %dir %{_localstatedir}/cache/%{name}
%{_sbindir}/kresd
%{_sbindir}/kresc
%{_libdir}/libkres.so.*
%{_libdir}/knot-resolver
%{_mandir}/man8/kresd.8.gz

%files devel
%{_includedir}/libkres
%{_libdir}/pkgconfig/libkres.pc
%{_libdir}/libkres.so

%if "x%{?rhel}" == "x"
%files doc
%dir %{_pkgdocdir}
%doc %{_pkgdocdir}/html
%endif

%changelog
* Fri Feb 16 2018 Tomas Krizek <tomas.krizek@nic.cz> - 2.1.0-1
- see NEWS or https://www.knot-resolver.cz/
- move spec file to upstream
