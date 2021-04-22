# knot-resolver-manager upstream packaging sources

Top level distro/ dir contains upstream packaging sources for native packages.

Files in this directory follow [apkg] conventions and apkg can be used to
create BIRD packages for various distros directly from upstream sources as
well as from upstream archives once available.

[apkg]: https://apkg.rtfd.io


## Create package from current repo commit

Create native packages using isolated builder (pbuilder, mock, ...):

    apkg build

If you're using VM, container or other disposable system, it's recommended to
build packages directly using -h/--host-build and -i/--install-dep:

    apkg build -Hi

To create source package:

    apkg srcpkg

