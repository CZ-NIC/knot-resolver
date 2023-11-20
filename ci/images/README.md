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

To build this image, you need to retrieve the Coverity Scan token from the
dashboard and pass it to the `build.sh` script using the `COVERITY_SCAN_TOKEN`
environment variable, e.g.:

```
$ COVERITY_SCAN_TOKEN=the_secret_token ./build.sh debian-11-coverity
```

Sometimes, the Coverity Scan binaries need to be updated in order to maintain
compatibility with the cloud service. Simply rebuild this image and push it to
the registry to achieve this, no other changes (e.g. to the `Dockerfile`) are
required.

### debian-buster (10)

Used to serve the same purpose as `debian-11`. As of 2022-03-09, it is still
used by some jobs (linters).

## Maintenance

The `ci/images/` directory contains utility scripts to build, push or update
the container images.

```
$ ./build.sh debian-11    # builds a debian-11 image locally
$ ./push.sh debian-11     # pushes the local image into target registry
$ ./update.sh debian-11   # utility wrapper that both builds and pushes the image
$ ./update.sh */          # use shell expansion of dirnames to update all images
```

By default, a branch of Knot DNS deemed to be stable is selected according to
the `vars.sh` file. To build an image for a different Knot DNS branch, set the
`KNOT_BRANCH` environment variable to the name of the branch, e.g.:

```
$ KNOT_BRANCH='3.2' ./update.sh debian-11
```
