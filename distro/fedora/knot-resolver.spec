%global _hardened_build 1

%define GPG_CHECK 0
%define VERSION DYNAMIC
%define repodir %{_builddir}/%{name}-%{version}

Name:           knot-resolver
Version:        %{VERSION}
Release:        1%{?dist}
Summary:        Caching full DNS Resolver

License:        GPLv3
URL:            https://www.knot-resolver.cz/
Source0:        knot-resolver-%{version}.tar.xz

# LuaJIT only on these arches
%if 0%{?rhel}
# RHEL 7 does not have aarch64 LuaJIT
ExclusiveArch: %{ix86} x86_64
%else
ExclusiveArch: %{arm} aarch64 %{ix86} x86_64
%endif

Source2:        kresd.conf
Source3:        root.keys

%if 0%{GPG_CHECK}
Source1:        knot-resolver-%{version}.tar.xz.asc
# PGP keys used to sign upstream releases
# Export with --armor using command from https://fedoraproject.org/wiki/PackagingDrafts:GPGSignatures
# Don't forget to update %%prep section when adding/removing keys
Source100:     gpgkey-B6006460B60A80E782062449E747DF1F9575A3AA.gpg.asc
Source101:     gpgkey-BE26EBB9CBE059B3910CA35BCE8DD6A1A50A21E4.gpg.asc
Source102:     gpgkey-4A8BA48C2AED933BD495C509A1FBA5F7EF8C4869.gpg.asc
BuildRequires:  gnupg2
%endif

BuildRequires:  pkgconfig(libknot) >= 2.6.4
BuildRequires:  pkgconfig(libzscanner) >= 2.3.1
BuildRequires:  pkgconfig(libdnssec) >= 2.3.1
BuildRequires:  pkgconfig(libuv)
BuildRequires:  pkgconfig(luajit) >= 2.0

BuildRequires:  pkgconfig(libedit)
BuildRequires:  pkgconfig(libmemcached) >= 1.0
BuildRequires:  pkgconfig(hiredis)
BuildRequires:  pkgconfig(libsystemd)

BuildRequires:  pkgconfig(cmocka)

BuildRequires:  systemd

BuildRequires:  doxygen
BuildRequires:  breathe
BuildRequires:  python-sphinx
BuildRequires:  python-sphinx_rtd_theme

# Lua 5.1 version of the libraries have different package names
%if 0%{?rhel}
Requires:       lua-socket
Requires:       lua-sec
%else
Requires:       lua-socket-compat
Requires:       lua-sec-compat
%endif

Requires(pre): shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
The Knot DNS Resolver is a caching full resolver implementation written in C
and LuaJIT, including both a resolver library and a daemon. Modular
architecture of the library keeps the core tiny and efficient, and provides
a state-machine like API for extensions.

The package is pre-configured as local caching resolver.
To start using it, start a single kresd instance:
# systemctl start kresd@1.service

If you run into issues with activation of the service or its sockets, either
update your selinux-policy package or turn off selinux (setenforce 0).
https://bugzilla.redhat.com/show_bug.cgi?id=1366968
https://bugzilla.redhat.com/show_bug.cgi?id=1543049

%package devel
Summary:        Development headers for Knot DNS Resolver
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The package contains development headers for Knot DNS Resolver.

%if 0%{?fedora}
# Disable doc package in EPEL - it missing fonts in sphinx_rtd_theme
# https://bugzilla.redhat.com/show_bug.cgi?id=1492884
%package doc
Summary:        Documentation for Knot DNS Resolver
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}

%description doc
Documentation for Knot DNS Resolver
%endif

%prep
%if 0%{GPG_CHECK}
export GNUPGHOME=./gpg-keyring
mkdir ${GNUPGHOME}
gpg2 --import %{SOURCE100} %{SOURCE101} %{SOURCE102}
gpg2 --verify %{SOURCE1} %{SOURCE0}
%endif
%setup -q -n %{name}-%{version}

rm -v scripts/bootstrap-depends.sh

%build
%global build_paths PREFIX=%{_prefix} BINDIR=%{_bindir} LIBDIR=%{_libdir} INCLUDEDIR=%{_includedir} ETCDIR=%{_sysconfdir}/knot-resolver
%global build_flags V=1 CFLAGS="%{optflags}" LDFLAGS="%{__global_ldflags}" %{build_paths} HAS_go=no
%make_build %{build_flags}

%if 0%{?fedora}
# build documentation
make doc
%endif

%install
%make_install %{build_flags}

# move sample configuration files to documentation
install -m 0755 -d %{buildroot}%{_pkgdocdir}
mv %{buildroot}%{_sysconfdir}/knot-resolver/config.* %{buildroot}%{_pkgdocdir}
chmod 0644 %{buildroot}%{_pkgdocdir}/config.*

# install configuration files
mkdir -p %{buildroot}%{_sysconfdir}
install -m 0755 -d %{buildroot}%{_sysconfdir}/knot-resolver
install -m 0644 -p %SOURCE2 %{buildroot}%{_sysconfdir}/knot-resolver/kresd.conf
install -m 0664 -p %SOURCE3 %{buildroot}%{_sysconfdir}/knot-resolver/root.keys

# install systemd units and doc
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 -p %{repodir}/systemd/kresd@.service %{buildroot}%{_unitdir}/kresd@.service
mkdir -p %{buildroot}%{_mandir}/man7
install -m 0644 -p %{repodir}/doc/kresd.systemd.7 %{buildroot}%{_mandir}/man7/kresd.systemd.7

%if 0%{?rhel}
mkdir -p %{buildroot}%{_unitdir}/kresd@.service.d
install -m 0644 -p %{repodir}/systemd/drop-in/systemd-compat.conf %{buildroot}%{_unitdir}/kresd@.service.d/override.conf
%endif
%if 0%{?fedora}
# no socket activation for CentOS 7 (requires systemd.227)
install -m 0644 -p %{repodir}/systemd/kresd.socket %{buildroot}%{_unitdir}/kresd.socket
install -m 0644 -p %{repodir}/systemd/kresd-control@.socket %{buildroot}%{_unitdir}/kresd-control@.socket
install -m 0644 -p %{repodir}/systemd/kresd-tls.socket %{buildroot}%{_unitdir}/kresd-tls.socket
%endif

# install tmpfiles.d
mkdir -p %{buildroot}%{_tmpfilesdir}
install -m 0644 -p %{repodir}/systemd/tmpfiles/knot-resolver.conf %{buildroot}%{_tmpfilesdir}/knot-resolver.conf
mkdir -p %{buildroot}%{_rundir}
install -m 0751 -d %{buildroot}%{_rundir}/knot-resolver

# install cache
mkdir -p %{buildroot}%{_localstatedir}/cache
install -m 0750 -d %{buildroot}%{_localstatedir}/cache/knot-resolver

# remove module with unsatisfied dependencies
rm -r %{buildroot}%{_libdir}/kdns_modules/{http,http.lua}

%check
# check-config requires installed version of kresd, do not attempt to run that
LD_PRELOAD=lib/libkres.so make check-unit %{build_flags} LDFLAGS="%{__global_ldflags} -ldl"

%pre
getent group knot-resolver >/dev/null || groupadd -r knot-resolver
getent passwd knot-resolver >/dev/null || useradd -r -g knot-resolver -d %{_sysconfdir}/knot-resolver -s /sbin/nologin -c "Knot DNS Resolver" knot-resolver

%post
%systemd_post system-kresd.slice
/sbin/ldconfig

# TODO: can be removed when Fedora 27 is no longer supported and migration is no longer necessary
# Migration script
if [ -f "/etc/kresd/config" ]; then
    echo -e '\n\n---------------------------------------------------------'
    echo '    WARNING: Migrating to knot-resolver 2.0'
    echo -e '---------------------------------------------------------\n'
    echo 'Please check your configuration still works, it has been moved to'
    echo '/etc/knot-resolver/kresd.conf'
    echo -e "\nTo start or enable the service, please use 'kresd@1.service', e.g.:"
    echo -e '  # systemctl start kresd@1.service\n\n'
    systemctl stop kresd.service kresd{,-tls,-control}.socket &>/dev/null ||:
    cp -r /etc/kresd/* /etc/knot-resolver/
    mv /etc/knot-resolver/config /etc/knot-resolver/kresd.conf
    chown -R root:knot-resolver /etc/knot-resolver
    sed -i 's#/etc/kresd#/etc/knot-resolver#' /etc/knot-resolver/kresd.conf
fi
if [ -d "/run/kresd" ]; then
    rm -f /run/kresd/control
    mv /run/kresd/* /var/cache/knot-resolver/ &>/dev/null
    chown -R knot-resolver:knot-resolver /var/cache/knot-resolver
fi

%preun
%systemd_preun system-kresd.slice

%postun
%systemd_postun_with_restart system-kresd.slice
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
%if 0%{?rhel}
%{_unitdir}/kresd@.service.d/override.conf
%endif
%if 0%{?fedora}
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

%if 0%{?fedora}
%files doc
%doc doc/html
%endif

%changelog
* Fri Feb 16 2018 Tomas Krizek <tomas.krizek@nic.cz> - 2.1.0-1
- see NEWS or https://www.knot-resolver.cz/
- move spec file to upstream
