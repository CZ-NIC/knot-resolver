.. SPDX-License-Identifier: GPL-3.0-or-later

Packaging tests
===============

Packaging tests used pytest, docker and each directory with subdirectory *.packaging*
is called as *component*.

Run tests for all components:

.. code-block::

  pytest -r fEsxX tests/packaging

List all components:

.. code-block::

  pytest tests/packaging --collect-only

Run test for specific component (*doc/.packaging*):

.. code-block::

  pytest -r fEsxX tests/packaging -k test_collect[debian_10-doc/.packaging]

.. note::

	For debug add argument :code:`-s`.

daemon/.packaging component
---------------------------

This is special component that is used by all others components.
For each distribution and version are created two docker images with this component.
One with building dependencies and one for running dependencies.
*Build docker image* is tagged as :code:`kr-packaging-tests-<distro><version>-build`
and *Run docker image* is tagged as :code:`kr-packaging-tests-<distro><version>-run`.

Others components
-----------------

All others components are based on *daemon/.packaging* component (docker image).
When component needs new building dependencies, new running dependencies
or some scripts that change build or run phase (see `File structure of each component`_),
new docker image is created.
*Build docker image* is tagged as :code:`kr-packaging-tests-<distro><version>-<component>-build`
and *Run docker image* is tagged as :code:`kr-packaging-tests-<distro><version>-<component>-run`.

File structure of each component
------------------------------------

* <distro>
  * <version>
    * builddeps - list of build depedencies
    * rundeps - list of runtime depedencies
    * pre-build.sh - script called before build phase
    * post-build.sh - script called after build phase
    * pre-run.sh - script called before run phase
    * post-run.sh - script called after run phase
    * install.sh and build.sh - scripts to rewrite standard commands for building and instaling knot-resolvers
    * pre-test.sh - script called immediately before testing
* test.config or test.sh - kresd config test or shell script (one of them must exists)

Commands order to create docker image
-------------------------------------

For *build docker image*:

#. run pre-build.sh
#. install packages specifed in the file *builddeps*
#. run build.sh
#. run install.sh
#. run post-build.sh

For *run docker image*:

#. run pre-run.sh
#. install packages specifed in the file *rundeps*
#. run pre-test.sh
#. run test (:code:`kresd -c test.config` or :code:`test.sh`)
#. run post-build.sh


.. note::

  knot-resolver builded in *build docker image* is automatically moved to *run docker image*.
