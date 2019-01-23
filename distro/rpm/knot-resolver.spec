%global _hardened_build 1
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}}

%define GPG_CHECK 0
%define VERSION __VERSION__
%define repodir %{_builddir}/%{name}-%{version}

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
BuildRequires:  pkgconfig(cmocka)
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(libedit)
BuildRequires:  pkgconfig(libknot) >= 2.7.2
BuildRequires:  pkgconfig(libzscanner) >= 2.7.2
BuildRequires:  pkgconfig(libdnssec) >= 2.7.2
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(libuv)
BuildRequires:  pkgconfig(luajit) >= 2.0
BuildRequires:  pkgconfig(systemd)

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
Requires:       lua-cqueues
Requires(pre):	shadow-utils
%endif
%if 0%{?suse_version}
BuildRequires:  lmdb-devel
BuildRequires:  python3-Sphinx
Requires:       lua51-luasocket
Requires:       lua51-luasec
Requires(pre):	shadow
%endif

%if "x%{?rhel}" == "x"
# dependencies for doc package; disable in EPEL (missing fonts)
# https://bugzilla.redhat.com/show_bug.cgi?id=1492884
BuildRequires:  doxygen
BuildRequires:  python3-breathe
BuildRequires:  python3-sphinx_rtd_theme
%endif

Requires(post):		systemd
Requires(preun):	systemd
Requires(postun):	systemd

%description
The Knot Resolver is a caching full resolver implementation written in C
and LuaJIT, including both a resolver library and a daemon. Modular
architecture of the library keeps the core tiny and efficient, and provides
a state-machine like API for extensions.

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
%global build_paths PREFIX=%{_prefix} BINDIR=%{_bindir} LIBDIR=%{_libdir} INCLUDEDIR=%{_includedir} ETCDIR=%{_sysconfdir}/knot-resolver
%global build_flags V=1 CFLAGS="%{optflags}" LDFLAGS="%{?__global_ldflags}" %{build_paths} HAS_go=no
%make_build %{build_flags}

%if "x%{?rhel}" == "x"
# build documentation
make doc
%endif

%check
make %{?_smp_mflags} check

%install
%make_install %{build_flags}

# move sample configuration files to documentation
install -m 0755 -d %{buildroot}%{_pkgdocdir}
mv %{buildroot}%{_sysconfdir}/knot-resolver/config.* %{buildroot}%{_pkgdocdir}
chmod 0644 %{buildroot}%{_pkgdocdir}/config.*

# install configuration files
mkdir -p %{buildroot}%{_sysconfdir}
install -m 0755 -d %{buildroot}%{_sysconfdir}/knot-resolver
install -m 0644 -p %{repodir}/distro/common/kresd.conf %{buildroot}%{_sysconfdir}/knot-resolver/kresd.conf
install -m 0664 -p %{repodir}/distro/common/root.keys %{buildroot}%{_sysconfdir}/knot-resolver/root.keys

# install systemd units and doc
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 -p %{repodir}/distro/common/systemd/kresd@.service %{buildroot}%{_unitdir}/kresd@.service
install -m 0644 -p %{repodir}/distro/common/systemd/kresd.target %{buildroot}%{_unitdir}/kresd.target
install -m 0755 -d %{buildroot}%{_unitdir}/multi-user.target.wants
ln -s ../kresd.target %{buildroot}%{_unitdir}/multi-user.target.wants/kresd.target
mkdir -p %{buildroot}%{_mandir}/man7
install -m 0644 -p %{repodir}/distro/common/systemd/kresd.systemd.7 %{buildroot}%{_mandir}/man7/kresd.systemd.7

%if 0%{?rhel}
# no socket activation for CentOS 7 (requires systemd.227)
mkdir -p %{buildroot}%{_unitdir}/kresd@.service.d
install -m 0644 -p %{repodir}/distro/common/systemd/drop-in/systemd-compat.conf %{buildroot}%{_unitdir}/kresd@.service.d/override.conf
%endif
%if "x%{?rhel}" == "x"
install -m 0644 -p %{repodir}/distro/common/systemd/kresd.socket %{buildroot}%{_unitdir}/kresd.socket
install -m 0644 -p %{repodir}/distro/common/systemd/kresd-control@.socket %{buildroot}%{_unitdir}/kresd-control@.socket
install -m 0644 -p %{repodir}/distro/common/systemd/kresd-tls.socket %{buildroot}%{_unitdir}/kresd-tls.socket
%endif

# install tmpfiles.d
mkdir -p %{buildroot}%{_tmpfilesdir}
install -m 0644 -p %{repodir}/distro/common/tmpfiles/knot-resolver.conf %{buildroot}%{_tmpfilesdir}/knot-resolver.conf
mkdir -p %{buildroot}%{_rundir}
install -m 0750 -d %{buildroot}%{_rundir}/knot-resolver

# install cache
mkdir -p %{buildroot}%{_localstatedir}/cache
install -m 0750 -d %{buildroot}%{_localstatedir}/cache/knot-resolver

# remove module with unsatisfied dependencies
rm -r %{buildroot}%{_libdir}/kdns_modules/{http,http.lua}

%pre
getent group knot-resolver >/dev/null || groupadd -r knot-resolver
getent passwd knot-resolver >/dev/null || useradd -r -g knot-resolver -d %{_sysconfdir}/knot-resolver -s /sbin/nologin -c "Knot Resolver" knot-resolver

%post
%systemd_post 'kresd@*.service'
/sbin/ldconfig

%preun
%systemd_preun 'kresd@*.service' kresd.target kresd.socket kresd-tls.socket

%postun
# NOTE: this doesn't restart the services on CentOS 7
%systemd_postun_with_restart 'kresd@*.service'
/sbin/ldconfig

%files
%license COPYING
%doc %{_pkgdocdir}
%attr(775,root,knot-resolver) %dir %{_sysconfdir}/knot-resolver
%attr(644,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/kresd.conf
%attr(664,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/root.keys
%attr(644,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/root.hints
%attr(644,root,knot-resolver) %config(noreplace) %{_sysconfdir}/knot-resolver/icann-ca.pem
%attr(750,knot-resolver,knot-resolver) %dir %{_localstatedir}/cache/knot-resolver
%{_unitdir}/kresd*.service
%{_unitdir}/kresd.target
%{_unitdir}/multi-user.target.wants/kresd.target
%if 0%{?rhel}
%{_unitdir}/kresd@.service.d/override.conf
%endif
%if "x%{?rhel}" == "x"
%{_unitdir}/kresd*.socket
%endif
%{_tmpfilesdir}/knot-resolver.conf
%{_sbindir}/kresd
%{_sbindir}/kresc
%{_libdir}/libkres.so.*
%{_libdir}/kdns_modules
%{_mandir}/man8/kresd.8.gz
%{_mandir}/man7/kresd.systemd.7.gz

%files devel
%{_includedir}/libkres
%{_libdir}/pkgconfig/libkres.pc
%{_libdir}/libkres.so

%if "x%{?rhel}" == "x"
%files doc
%doc doc/html
%endif

%changelog
* Fri Feb 16 2018 Tomas Krizek <tomas.krizek@nic.cz> - 2.1.0-1
- see NEWS or https://www.knot-resolver.cz/
- move spec file to upstream
