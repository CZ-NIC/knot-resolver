# SPDX-License-Identifier: GPL-3.0-or-later

%global _hardened_build 1
%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}}

%define GPG_CHECK 0
%define repodir %{_builddir}/%{name}-%{version}
%define NINJA ninja-build

Name:           knot-resolver
Version:        {{ version }}
Release:        cznic.{{ release }}%{?dist}
Summary:        Caching full DNS Resolver

License:        GPL-3.0-or-later
URL:            https://www.knot-resolver.cz/
Source0:        knot-resolver-%{version}.tar.xz
%if 0%{GPG_CHECK}
Source1:        knot-resolver-%{version}.tar.xz.asc
# PGP keys used to sign upstream releases
# Export with --armor using command from https://fedoraproject.org/wiki/PackagingDrafts:GPGSignatures
# Don't forget to update %%prep section when adding/removing keys
# This key is from: https://secure.nic.cz/files/knot-resolver/kresd-keyblock.asc
Source100:      kresd-keyblock.asc
BuildRequires:  gnupg2
%endif

Provides:       knot-resolver6 = %{version}-%{release}

# alpha packaging compat, can be removed around 6.2
Conflicts:      knot-resolver-core
Conflicts:      knot-resolver-manager

# LuaJIT only on these arches
ExclusiveArch:	%{arm} aarch64 %{ix86} x86_64

BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  meson
BuildRequires:  pkgconfig(cmocka)
BuildRequires:  pkgconfig(gnutls)
BuildRequires:  pkgconfig(libknot) >= 3.0.2
BuildRequires:  pkgconfig(libzscanner) >= 3.0.2
BuildRequires:  pkgconfig(libdnssec) >= 3.0.2
BuildRequires:  pkgconfig(libnghttp2)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(libcap-ng)
BuildRequires:  pkgconfig(libuv)
BuildRequires:  pkgconfig(luajit) >= 2.0
BuildRequires:  jemalloc-devel
BuildRequires:  python3-devel

Requires:       systemd
Requires(post): systemd

# manager dependencies
Requires:       python3
Requires:       python3-aiohttp
Requires:       supervisor
%if 0%{?suse_version}
Requires:       python3-PyYAML
Requires:       python3-typing_extensions
%else
Requires:       python3-pyyaml
Requires:       python3-typing-extensions
%endif
Recommends:     python3-prometheus_client
Recommends:     python3-watchdog

# dnstap module dependencies
# SUSE is missing protoc-c protobuf compiler
%if "x%{?suse_version}" == "x"
BuildRequires:  pkgconfig(libfstrm)
BuildRequires:  pkgconfig(libprotobuf-c)
%endif

# Distro-dependent dependencies
%if 0%{?rhel} == 7
BuildRequires:  lmdb-devel
# Lua 5.1 version of the libraries have different package names
Requires:       lua-basexx
Requires:       lua-psl
Requires:       lua-http
Requires(pre):  shadow-utils
%endif
%if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires:  pkgconfig(lmdb)
Requires:       lua5.1-basexx
Requires:       lua5.1-cqueues
Requires:       lua5.1-http
Recommends:     lua5.1-psl
Requires(pre):  shadow-utils
%endif

# we do not build HTTP module on SuSE so the build requires is not needed
%if "x%{?suse_version}" == "x"
BuildRequires:  openssl-devel
%endif

%if 0%{?suse_version}
%define NINJA ninja
BuildRequires:  lmdb-devel
BuildRequires:  python3-setuptools
Requires(pre):  shadow
%endif

%description
The Knot Resolver is a DNSSEC-enabled caching full resolver implementation
written in C and LuaJIT, including both a resolver library and a daemon.
Modular architecture of the library keeps the core tiny and efficient, and
provides a state-machine like API for extensions.

Knot Resolver Manager is a configuration tool for Knot Resolver. The Manager
hides the complexity of running several independent resolver processes while
ensuring zero-downtime reconfiguration with YAML/JSON declarative
configuration and an optional HTTP API for dynamic changes.


%package devel
Summary:        Development headers for Knot Resolver
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
The package contains development headers for Knot Resolver.

%if "x%{?suse_version}" == "x"
%package module-dnstap
Summary:        dnstap module for Knot Resolver
Requires:       %{name} = %{version}-%{release}

%description module-dnstap
dnstap module for Knot Resolver supports logging DNS responses to a unix socket
in dnstap format using fstrm framing library.  This logging is useful if you
need effectively log all DNS traffic.
%endif

%if "x%{?suse_version}" == "x"
%package module-http
Summary:        HTTP module for Knot Resolver
Requires:       %{name} = %{version}-%{release}
%if 0%{?fedora} || 0%{?rhel} > 7
Requires:       lua5.1-http
Requires:       lua5.1-mmdb
%else
Requires:       lua-http
Requires:       lua-mmdb
%endif

%description module-http
HTTP module for Knot Resolver can serve as API endpoint for other modules or
provide a web interface for local visualization of the resolver cache and
queries. It can also serve DNS-over-HTTPS, but it is deprecated in favor of
native C implementation, which doesn't require this package.
%endif

%prep
%if 0%{GPG_CHECK}
export GNUPGHOME=./gpg-keyring
mkdir -m 700 ${GNUPGHOME}
gpg2 --import %{SOURCE100}
gpg2 --verify %{SOURCE1} %{SOURCE0}
%endif
%setup -q -n %{name}-%{version}

%build
CFLAGS="%{optflags}" LDFLAGS="%{?__global_ldflags}" meson build_rpm \
    -Dsystemd_files=enabled \
%if "x%{?suse_version}" == "x"
    -Ddnstap=enabled \
%endif
    -Dunit_tests=enabled \
    -Dmanaged_ta=enabled \
    -Dkeyfile_default="%{_sharedstatedir}/knot-resolver/root.keys" \
    -Dinstall_root_keys=enabled \
    -Dmalloc=jemalloc \
    --buildtype=plain \
    --prefix="%{_prefix}" \
    --sbindir="%{_sbindir}" \
    --libdir="%{_libdir}" \
    --includedir="%{_includedir}" \
    --sysconfdir="%{_sysconfdir}" \

%{NINJA} -v -C build_rpm

%py3_build

%install
DESTDIR="${RPM_BUILD_ROOT}" %{NINJA} -v -C build_rpm install

# add knot-resolver.service to multi-user.target.wants to support enabling kresd services
install -m 0755 -d %{buildroot}%{_unitdir}/multi-user.target.wants
ln -s ../knot-resolver.service %{buildroot}%{_unitdir}/multi-user.target.wants/knot-resolver.service

# remove modules with missing dependencies
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/etcd.lua

# remove unused sysusers
rm %{buildroot}%{_prefix}/lib/sysusers.d/knot-resolver.conf

%if 0%{?suse_version}
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/experimental_dot_auth.lua
rm -r %{buildroot}%{_libdir}/knot-resolver/kres_modules/http
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/http*.lua
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/prometheus.lua
%endif

# rename doc directory for centos 7, opensuse
%if 0%{?suse_version} || 0%{?rhel} == 7
install -m 755 -d %{buildroot}/%{_pkgdocdir}
mv %{buildroot}/%{_datadir}/doc/%{name}/* %{buildroot}/%{_pkgdocdir}/
%endif

# install knot_resolver python module
%py3_install

install -m 644 -D etc/config/config.yaml %{buildroot}%{_sysconfdir}/knot-resolver/config.yaml

%pre
getent group knot-resolver >/dev/null || groupadd -r knot-resolver
getent passwd knot-resolver >/dev/null || useradd -r -g knot-resolver -d %{_sysconfdir}/knot-resolver -s /sbin/nologin -c "Knot Resolver" knot-resolver

%post
# systemd_post macro is not needed for anything (calls systemctl preset)
%tmpfiles_create %{_tmpfilesdir}/knot-resolver.conf
%if "x%{?fedora}" == "x"
/sbin/ldconfig
%endif

%preun
%systemd_preun knot-resolver.service

%postun
%systemd_postun_with_restart knot-resolver.service
%if "x%{?fedora}" == "x"
/sbin/ldconfig
%endif


%files
%dir %{_pkgdocdir}
%license %{_pkgdocdir}/COPYING
%doc %{_pkgdocdir}/AUTHORS
%doc %{_pkgdocdir}/NEWS
%doc %{_pkgdocdir}/examples
%dir %{_sysconfdir}/knot-resolver
%config(noreplace) %{_sysconfdir}/knot-resolver/config.yaml
%config(noreplace) %{_sysconfdir}/knot-resolver/root.hints
%{_sysconfdir}/knot-resolver/icann-ca.pem
%attr(750,knot-resolver,knot-resolver) %dir %{_sharedstatedir}/knot-resolver
%attr(640,knot-resolver,knot-resolver) %{_sharedstatedir}/knot-resolver/root.keys
%dir %{_unitdir}/multi-user.target.wants
%{_unitdir}/knot-resolver.service
%{_unitdir}/multi-user.target.wants/knot-resolver.service
%{_tmpfilesdir}/knot-resolver.conf
%ghost /run/%{name}
%ghost %{_localstatedir}/cache/%{name}
%attr(750,knot-resolver,knot-resolver) %dir %{_libdir}/%{name}
%{_bindir}/kresctl
%{_bindir}/knot-resolver
%{_sbindir}/kresd
%{_sbindir}/kres-cache-gc
%{_libdir}/libkres.so.*
%{_libdir}/knot-resolver/*.so
%{_libdir}/knot-resolver/*.lua
%dir %{_libdir}/knot-resolver/kres_modules
%{_libdir}/knot-resolver/kres_modules/bogus_log.so
%{_libdir}/knot-resolver/kres_modules/edns_keepalive.so
%{_libdir}/knot-resolver/kres_modules/extended_error.so
%{_libdir}/knot-resolver/kres_modules/hints.so
%{_libdir}/knot-resolver/kres_modules/nsid.so
%{_libdir}/knot-resolver/kres_modules/refuse_nord.so
%{_libdir}/knot-resolver/kres_modules/stats.so
%{_libdir}/knot-resolver/kres_modules/daf
%{_libdir}/knot-resolver/kres_modules/daf.lua
%{_libdir}/knot-resolver/kres_modules/detect_time_jump.lua
%{_libdir}/knot-resolver/kres_modules/detect_time_skew.lua
%{_libdir}/knot-resolver/kres_modules/dns64.lua
%if "x%{?suse_version}" == "x"
%{_libdir}/knot-resolver/kres_modules/experimental_dot_auth.lua
%endif
%{_libdir}/knot-resolver/kres_modules/graphite.lua
%{_libdir}/knot-resolver/kres_modules/policy.lua
%{_libdir}/knot-resolver/kres_modules/predict.lua
%{_libdir}/knot-resolver/kres_modules/prefetch.lua
%{_libdir}/knot-resolver/kres_modules/prefill.lua
%{_libdir}/knot-resolver/kres_modules/priming.lua
%{_libdir}/knot-resolver/kres_modules/rebinding.lua
%{_libdir}/knot-resolver/kres_modules/renumber.lua
%{_libdir}/knot-resolver/kres_modules/serve_stale.lua
%{_libdir}/knot-resolver/kres_modules/ta_sentinel.lua
%{_libdir}/knot-resolver/kres_modules/ta_signal_query.lua
%{_libdir}/knot-resolver/kres_modules/ta_update.lua
%{_libdir}/knot-resolver/kres_modules/view.lua
%{_libdir}/knot-resolver/kres_modules/watchdog.lua
%{_libdir}/knot-resolver/kres_modules/workarounds.lua
%{python3_sitearch}/knot_resolver*
%{_mandir}/man8/kresd.8.gz
%{_mandir}/man8/kresctl.8.gz

%files devel
%{_includedir}/libkres
%{_libdir}/pkgconfig/libkres.pc
%{_libdir}/libkres.so

%if "x%{?suse_version}" == "x"
%files module-dnstap
%{_libdir}/knot-resolver/kres_modules/dnstap.so
%endif

%if "x%{?suse_version}" == "x"
%files module-http
%{_libdir}/knot-resolver/debug_opensslkeylog.so
%{_libdir}/knot-resolver/kres_modules/http
%{_libdir}/knot-resolver/kres_modules/http*.lua
%{_libdir}/knot-resolver/kres_modules/prometheus.lua
%endif

%changelog
* {{ now }} Jakub Ružička <jakub.ruzicka@nic.cz> - {{ version }}-{{ release }}
- upstream package
- see NEWS or https://www.knot-resolver.cz/
