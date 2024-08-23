# Knot Resolver scripts

These are auxillary scripts used for Knot Resolver development.

The scripts in the root of this directory are meant to be executed directly by
developers.  Some may also be run by automated tools.

There are also the following subdirectories.  The scripts in these are *only
ever* meant to be run by automated tools:

- `ci`: specific to the CI/CD pipeline
- `lib`: (potentially) generally useful scripts to be called by other scripts
- `meson`: specific to the build system
- `poe-tasks`: run by the `poe` script in the repository root
  - `utils`: scripts additionally called by the `poe` tasks

For more information about each script, see its content for explanatory
comments.
