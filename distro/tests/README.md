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

By default, the *knot-resolver-devel* repo (for knot-resolver) along
with *knot-resolver-latest* (for knot) is used. To test only the
*knot-resolver-latest* repo, set it in `repos.yaml` (or use the
test-distro.sh script which overwrites this file). If you're running
tests in parallel, they all HAVE TO use the same repo(s).

Run the following command for every distro (aka directory with
Vagrantfile):

```
./test-distro.sh knot-resolver-devel debian9
```

or

```
./test-distro.sh knot-resolver-testing debian9
```

or

```
./test-distro.sh knot-resolver-latest debian9
```

At the end of the test, the package version that was tested is
printed out. Make sure you're testing what you intended to.
