zypper addrepo https://download.opensuse.org/repositories/home:CZ-NIC:knot-resolver-latest/openSUSE_Leap_15.2/home:CZ-NIC:knot-resolver-latest.repo
zypper --no-gpg-checks refresh
zypper install -y knot-resolver
