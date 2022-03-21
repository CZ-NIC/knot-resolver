# Container images for CI

## Image purpose

### debian-11

The main image used by shared runners to execute most CI builds and tests.

### debian-11-coverity

A stripped down version of `debian-11`. It only contains build (not test)
dependencies of `kresd`. It also contains the `cov-build` tool for generating
inputs for [Coverity Scan](https://scan.coverity.com/).

It is used by the `coverity` CI job to generate and send data to Coverity Scan
for analysis.

### debian-bullseye

Used to serve the same purpose as `debian-11`. As of 2022-03-09, it is still
used by some jobs (linters).

### lxc-debian-11

Very similar to the main image. The main difference is a custom base image
which can be used for LXC runners and boots into systemd. It is useful to
update it when `debian-11` gets updated, as it will allow some of the tests to
be migrated to the LXC runners in the future (especially the
unstable/problematic ones - pytests already migrated, deckard might be a good
candidate).

## Maintenance

The `ci/images/` directory contains utility scripts to build, push or update
the container images.

```
$ ./build.sh debian-11    # builds a debian-11 image locally
$ ./push.sh debian-11     # pushes the local image into target registry
$ ./update.sh debian-11   # utility wrapper that both builds and pushes the image
$ ./update.sh */          # use shell expansion of dirnames to update all images
```
