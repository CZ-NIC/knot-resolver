Requirements
------------

- ansible
- vagrant
- libvirt (+vagrant-libvirt) / virtualbox

Usage
-----

`vagrant up` command is configured to trigger ansible provisioning
which configures OBS repository, installs the knot-resolver package,
starts the kresd@1 service and finally attempts to use it to resolve
a domain name. It also tests that DNSSEC validation is turned on.

By default, the *knot-resolver-latest* repo is used. To test the
*knot-resolver-devel* repo, enable in it `knot-resolver-test.yaml`.

Run the following command for every distro (aka directory with
Vagrantfile):

./test-distro.sh debian9

Caveats
-------

This tests the latest `knot-resolver` package that is available. In certain
cases, this may result in unexpected behaviour, because it might be testing a
different package than expected.

