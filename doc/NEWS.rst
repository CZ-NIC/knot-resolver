.. SPDX-License-Identifier: GPL-3.0-or-later

.. _release_notes:

*************
Release notes
*************

Version numbering
=================
Version number format is ``major.minor.patch``.
Knot Resolver does not use semantic versioning even though the version number looks similar.

Leftmost number which was changed signalizes what to expect when upgrading:

Major version
    * Manual upgrade steps might be necessary, please follow instructions in :ref:`Upgrading` section.
    * Major releases may contain significant changes including changes to configuration format.
    * We might release a new major also when internal implementation details change significantly.

Minor version
   * Configuration stays compatible with the previous version, except for undocumented or very obscure options.
   * Upgrade should be seamless for users who use modules shipped as part of Knot Resolver distribution.
   * Incompatible changes in internal APIs are allowed in minor versions. Users who develop or use custom modules
     (i.e. modules not distributed together with Knot Resolver) need to double check their modules for incompatibilities.
     :ref:`Upgrading` section should contain hints for module authors.

Patch version
    * Everything should be compatible with the previous version.
    * API for modules should be stable on best effort basis, i.e. API is very unlikely to break in patch releases.
    * Custom modules might need to be recompiled, i.e. ABI compatibility is not guaranteed.

This definition is not applicable to versions older than 5.2.0.

.. include:: ../NEWS

