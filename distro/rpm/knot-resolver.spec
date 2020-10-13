# SPDX-License-Identifier: GPL-3.0-or-later

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

License:        GPL-3.0-or-later
URL:            https://www.knot-resolver.cz/
Source0:        knot-resolver_%{version}.orig.tar.xz

# LuaJIT only on these arches
%if 0%{?rhel} == 7
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
BuildRequires:  pkgconfig(libknot) >= 2.8
BuildRequires:  pkgconfig(libzscanner) >= 2.8
BuildRequires:  pkgconfig(libdnssec) >= 2.8
BuildRequires:  pkgconfig(libnghttp2)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(libcap-ng)
BuildRequires:  pkgconfig(libuv)
BuildRequires:  pkgconfig(luajit) >= 2.0

Requires:       systemd
Requires(post): systemd

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
BuildRequires:  python3-sphinx
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
BuildRequires:  python3-Sphinx
Requires(pre):  shadow
%endif

%if "x%{?rhel}" == "x"
# dependencies for doc package
# NOTE: doc isn't possible to build on CentOS 7, 8
#       python2-sphinx is too old and python36-breathe is broken on CentOS 7
#       python3-breathe isn't available for CentOS 8 (yet? rhbz#1808766)
BuildRequires:  doxygen
BuildRequires:  python3-breathe
BuildRequires:  python3-sphinx_rtd_theme
BuildRequires:  texinfo
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
mkdir ${GNUPGHOME}
gpg2 --import %{SOURCE100} %{SOURCE101} %{SOURCE102}
gpg2 --verify %{SOURCE1} %{SOURCE0}
%endif
%setup -q -n %{name}-%{version}

%build
CFLAGS="%{optflags}" LDFLAGS="%{?__global_ldflags}" meson build_rpm \
%if "x%{?rhel}" == "x"
    -Ddoc=enabled \
%endif
    -Dsystemd_files=enabled \
    -Dclient=enabled \
    -Dunit_tests=enabled \
    -Dmanaged_ta=enabled \
    -Dkeyfile_default="%{_sharedstatedir}/knot-resolver/root.keys" \
    -Dinstall_root_keys=enabled \
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

%pre
getent group knot-resolver >/dev/null || groupadd -r knot-resolver
getent passwd knot-resolver >/dev/null || useradd -r -g knot-resolver -d %{_sysconfdir}/knot-resolver -s /sbin/nologin -c "Knot Resolver" knot-resolver

%if "x%{?rhel}" == "x"
# upgrade-4-to-5
if [ -f %{_unitdir}/kresd.socket ] ; then
	export UPG_DIR=%{_sharedstatedir}/knot-resolver/.upgrade-4-to-5
	mkdir -p ${UPG_DIR}
	touch ${UPG_DIR}/.unfinished

	for sock in kresd.socket kresd-tls.socket kresd-webmgmt.socket kresd-doh.socket ; do
		if systemctl is-enabled ${sock} 2>/dev/null | grep -qv masked ; then
			systemctl show ${sock} -p Listen > ${UPG_DIR}/${sock}
			case "$(systemctl show ${sock} -p BindIPv6Only)" in
			*ipv6-only)
				touch ${UPG_DIR}/${sock}.v6only
				;;
			*default)
				if cat /proc/sys/net/ipv6/bindv6only | grep -q 1 ; then
					touch ${UPG_DIR}/${sock}.v6only
				fi
				;;
			esac
		fi
	done
fi
%endif


%post
# upgrade-4-to-5
%if "x%{?rhel}" == "x"
export UPG_DIR=%{_sharedstatedir}/knot-resolver/.upgrade-4-to-5
if [ -f ${UPG_DIR}/.unfinished ] ; then
	rm -f ${UPG_DIR}/.unfinished
	kresd -c %{_libdir}/knot-resolver/upgrade-4-to-5.lua &>/dev/null
	echo -e "\n   !!! WARNING !!!"
	echo -e "Knot Resolver configuration file requires manual upgrade.\n"
	cat ${UPG_DIR}/kresd.conf.net 2>/dev/null
fi
%endif

# 5.0.1 fix to force restart of kres-cache-gc.service, which was missing in systemd_postun_with_restart
# TODO: remove once most users upgrade to 5.0.1+
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 2 ] ; then
        systemctl try-restart kres-cache-gc.service >/dev/null 2>&1 || :
fi

# systemd_post macro is not needed for anything (calls systemctl preset)
%tmpfiles_create %{_tmpfilesdir}/knot-resolver.conf
%if "x%{?fedora}" == "x"
/sbin/ldconfig
%endif

%preun
%systemd_preun kres-cache-gc.service kresd.target

%postun
%systemd_postun_with_restart 'kresd@*.service' kres-cache-gc.service
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
%config(noreplace) %{_sysconfdir}/knot-resolver/kresd.conf
%config(noreplace) %{_sysconfdir}/knot-resolver/root.hints
%{_sysconfdir}/knot-resolver/icann-ca.pem
%attr(750,knot-resolver,knot-resolver) %dir %{_sharedstatedir}/knot-resolver
%attr(640,knot-resolver,knot-resolver) %{_sharedstatedir}/knot-resolver/root.keys
%{_unitdir}/kresd@.service
%{_unitdir}/kres-cache-gc.service
%{_unitdir}/kresd.target
%dir %{_unitdir}/multi-user.target.wants
%{_unitdir}/multi-user.target.wants/kresd.target
%{_mandir}/man7/kresd.systemd.7.gz
%{_tmpfilesdir}/knot-resolver.conf
%ghost /run/%{name}
%ghost %{_localstatedir}/cache/%{name}
%attr(750,knot-resolver,knot-resolver) %dir %{_libdir}/%{name}
%{_sbindir}/kresd
%{_sbindir}/kresc
%{_sbindir}/kres-cache-gc
%{_libdir}/libkres.so.*
%dir %{_libdir}/knot-resolver
%{_libdir}/knot-resolver/*.so
%{_libdir}/knot-resolver/*.lua
%dir %{_libdir}/knot-resolver/kres_modules
%{_libdir}/knot-resolver/kres_modules/*.so
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

%files devel
%{_includedir}/libkres
%{_libdir}/pkgconfig/libkres.pc
%{_libdir}/libkres.so

%if "x%{?rhel}" == "x"
%files doc
%dir %{_pkgdocdir}
%doc %{_pkgdocdir}/html
%doc %{_datadir}/info/knot-resolver.info*
%endif

%if "x%{?suse_version}" == "x"
%files module-http
%{_libdir}/knot-resolver/debug_opensslkeylog.so
%{_libdir}/knot-resolver/kres_modules/http
%{_libdir}/knot-resolver/kres_modules/http*.lua
%{_libdir}/knot-resolver/kres_modules/prometheus.lua
%endif

%changelog
* Fri Feb 16 2018 Tomas Krizek <tomas.krizek@nic.cz> - 2.1.0-1
- see NEWS or https://www.knot-resolver.cz/
- move spec file to upstream
