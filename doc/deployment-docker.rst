******
Docker
******


.. note::

    Before version 6, our Docker images were not meant to be used in production. This is no longer the case and with the introduction of ``kres-manager``, Knot Resolver runs in containers without any issues.

An official Docker image can be found on `Docker Hub <https://hub.docker.com/r/cznic/knot-resolver>`_. The image contains Knot Resolver as if it was installed from our official distro packages.

.. code-block:: bash

    docker run --rm -ti -P docker.io/cznic/knot-resolver

The configuration file is located at ``/etc/knot-resolver/config.yml`` and the cache is at ``/var/cache/knot-resolver``. Having persistent cache in a mounted volume will help a lot with performance just after restart.

.. warning::
    
    While the container image contains normal installation of Knot Resolver and there shouldn't be any differences between running it natively and in a container, we (the developers) do not have any experience using the Docker image in production. Especially, beware of running the DNS resolver with a software defined network (i.e. in Kubernetes). There will likely be some performance penalties for doing so. We haven't done any measurements comparing different types of installations so we don't know the performance differences. If you have done some measurements yourself, please reach out to us and we will share it here with everyone else.
    