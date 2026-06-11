# SPDX-License-Identifier: GPL-3.0-or-later
#
# Supported:
#   RHEL 9+
#   Fedora 42+
#   openSUSE Leap 16.0+ / Tumbleweed

%if 0%{?rhel} && 0%{?rhel} < 9
%warning RHEL version: %{?rhel}
%error RHEL versions older than 9 are unsupported
%endif

%if 0%{?fedora} && 0%{?fedora} < 42
%warning Fedora version: %{?fedora}
%error Fedora versions older than 42 are unsupported
%endif

%if 0%{?suse_version} && 0%{?suse_version} < 1600
%warning openSUSE Leap version: %{?suse_version}
%error openSUSE Leap versions older than 16.0 are unsupported
%endif

# Reject unsupported distros entirely
%if !0%{?rhel} && !0%{?fedora} && !0%{?suse_version}
%error Unsupported distribution
%endif

# Create a build option to check GPG signature (--with gpg_check)
%bcond_with gpg_check

Name:           knot-resolver
Version:        {{ version }}
Release:        cznic.{{ release }}%{?dist}
Summary:        Caching full DNS Resolver

License:        GPL-3.0-or-later
URL:            https://www.knot-resolver.cz/
Source0:        knot-resolver-%{version}.tar.xz

%if %{with gpg_check}
Source1:        knot-resolver-%{version}.tar.xz.asc
# PGP keys used to sign upstream releases
# Export with --armor using command from https://fedoraproject.org/wiki/PackagingDrafts:GPGSignatures
# Don't forget to update %%prep section when adding/removing keys
# This key is from: https://secure.nic.cz/files/knot-resolver/kresd-keyblock.asc
Source2:        kresd-keyblock.asc
BuildRequires:  gnupg2
%endif

Provides:       knot-resolver6 = %{version}-%{release}
Provides:       user(knot-resolver)
Provides:       group(knot-resolver)

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
BuildRequires: python3-poetry-core

BuildRequires:  systemd-rpm-macros
Requires:       systemd

Requires(pre): user(knot-resolver)
Requires(pre): group(knot-resolver)

# manager dependencies
Requires:       python3
Requires:       python3-aiohttp
Requires:       supervisor
%if 0%{?suse_version}
Requires:       python3-Jinja2
Requires:       python3-PyYAML
Requires:       python3-typing_extensions
%else
Requires:       python3-jinja2
Requires:       python3-pyyaml
Requires:       python3-typing-extensions
%endif
Recommends:     python3-prometheus_client
Recommends:     python3-watchdog

# dnstap module dependencies
# SUSE is missing protoc protobuf compiler
%if !0%{?suse_version}
BuildRequires:  pkgconfig(libfstrm)
BuildRequires:  pkgconfig(libprotobuf-c)
%endif

# Distro-dependent dependencies
%if 0%{?fedora} || 0%{?rhel}
BuildRequires:  pkgconfig(lmdb)
Requires:       lua5.1-basexx
Requires:       lua5.1-cqueues
Requires:       lua5.1-http
Recommends:     lua5.1-psl
%endif

# we do not build HTTP module on SuSE so the build requires is not needed
%if !0%{?suse_version}
BuildRequires:  openssl-devel
%endif

%if 0%{?suse_version}
BuildRequires:  lmdb-devel
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

%if !0%{?suse_version}
%package module-dnstap
Summary:        dnstap module for Knot Resolver
Requires:       %{name} = %{version}-%{release}

%description module-dnstap
dnstap module for Knot Resolver supports logging DNS responses to a unix socket
in dnstap format using fstrm framing library.  This logging is useful if you
need effectively log all DNS traffic.

%package module-http
Summary:        HTTP module for Knot Resolver
Requires:       %{name} = %{version}-%{release}
Requires:       lua5.1-http
Requires:       lua5.1-mmdb

%description module-http
HTTP module for Knot Resolver can serve as API endpoint for other modules or
provide a web interface for local visualization of the resolver cache and
queries. It can also serve DNS-over-HTTPS, but it is deprecated in favor of
native C implementation, which doesn't require this package.
%endif

%prep
%if %{with gpg_check}
export GNUPGHOME=%{_builddir}/gpg-keyring
install -dm 0700 ${GNUPGHOME}
gpg2 --import %{SOURCE2}
gpg2 --verify %{SOURCE1} %{SOURCE0}
%endif
%autosetup -p1 -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%meson \
    -Dsystemd_files=enabled \
%if !0%{?suse_version}
    -Ddnstap=enabled \
%endif
    -Dunit_tests=enabled \
    -Dmanaged_ta=enabled \
    -Dkeyfile_default="%{_sharedstatedir}/knot-resolver/root.keys" \
    -Dinstall_root_keys=enabled \
    -Dmalloc=jemalloc

%meson_build

%pyproject_wheel

%install
%meson_install

# remove modules with missing dependencies
rm %{buildroot}%{_libdir}/knot-resolver/kres_modules/etcd.lua

%if 0%{?suse_version}
rm -f %{buildroot}%{_libdir}/knot-resolver/kres_modules/experimental_dot_auth.lua
rm -rf %{buildroot}%{_libdir}/knot-resolver/kres_modules/http
rm -f %{buildroot}%{_libdir}/knot-resolver/kres_modules/http*.lua
rm -f %{buildroot}%{_libdir}/knot-resolver/kres_modules/prometheus.lua
%endif

%if 0%{?suse_version}
install -dm 0755 -d %{buildroot}%{_docdir}/%{name}
mv %{buildroot}%{_datadir}/doc/%{name}/* %{buildroot}%{_docdir}/%{name}/
%endif

# install knot_resolver python module
%pyproject_install
%pyproject_save_files
install -Dm 0644 etc/config/config.yaml %{buildroot}%{_sysconfdir}/knot-resolver/config.yaml

%post
%systemd_post knot-resolver.service

%preun
%systemd_preun knot-resolver.service

%postun
%systemd_postun_with_restart knot-resolver.service
%ldconfig_scriptlet

%files -f %{pyproject_files}
%dir %{_docdir}/%{name}
%license %{_docdir}/%{name}/COPYING
%doc %{_docdir}/%{name}/AUTHORS
%doc %{_docdir}/%{name}/NEWS
%doc %{_docdir}/%{name}/examples
%dir %{_sysconfdir}/knot-resolver
%config(noreplace) %{_sysconfdir}/knot-resolver/config.yaml
%config(noreplace) %{_sysconfdir}/knot-resolver/root.hints
%{_sysconfdir}/knot-resolver/icann-ca.pem
%{_sysusersdir}/knot-resolver.conf
%attr(750,knot-resolver,knot-resolver) %dir %{_sharedstatedir}/knot-resolver
%attr(640,knot-resolver,knot-resolver) %{_sharedstatedir}/knot-resolver/root.keys
%{_unitdir}/knot-resolver.service
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
%if !0%{?suse_version}
%{_libdir}/knot-resolver/kres_modules/experimental_dot_auth.lua
%endif
%{_libdir}/knot-resolver/kres_modules/fallback.lua
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
%{_mandir}/man8/kresd.8.gz
%{_mandir}/man8/kresctl.8.gz
%{_datadir}/bash-completion/completions/kresctl

%files devel
%{_includedir}/libkres
%{_libdir}/pkgconfig/libkres.pc
%{_libdir}/libkres.so

%if !0%{?suse_version}
%files module-dnstap
%{_libdir}/knot-resolver/kres_modules/dnstap.so
%endif

%if !0%{?suse_version}
%files module-http
%{_libdir}/knot-resolver/debug_opensslkeylog.so
%{_libdir}/knot-resolver/kres_modules/http
%{_libdir}/knot-resolver/kres_modules/http*.lua
%{_libdir}/knot-resolver/kres_modules/prometheus.lua
%endif

%changelog
* {{ now }} Knot Resolver team <knot-resolver@labs.nic.cz> - {{ version }}-{{ release }}
- upstream package
- see NEWS or https://www.knot-resolver.cz/
