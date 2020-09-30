# SPDX-License-Identifier: GPL-3.0-or-later

zypper addrepo https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-build/openSUSE_Leap_15.2/home:CZ-NIC:knot-resolver-build.repo
zypper --no-gpg-checks refresh
zypper install -y knot

