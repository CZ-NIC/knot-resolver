******
Docker
******

.. note::

    Before version 6, our Docker images were not intended for production use due to the lack of ``systemd`` in Docker and
    the inability to manage the multiple independent parts of the resolver.
    This is no longer the case since the introduction of the Manager that automatically control other parts of the resolver.

Knot Resolver official Docker image can be found at `Docker Hub <https://hub.docker.com/r/cznic/knot-resolver>`_.
First you can try running the container in interactive mode.

.. code-block:: bash

    $ docker run --rm -ti --network host docker.io/cznic/knot-resolver:6

For more robust deployments you will also probably need to configure network, for that see `Docker networking <https://docs.docker.com/engine/network/>`_.

Now you can try sending a query to the resolver using `kdig <https://www.knot-dns.cz/docs/latest/html/man_kdig.html>`_.

.. code-block:: bash

    $ kdig example.com @127.0.0.1
    $ kdig nic.cz @127.0.0.1#443 +https

The image contains full Knot Resolver installation, so there shouldn't be much difference between running it natively and running it in a container.
The configuration file is located at ``/etc/knot-resolver/config.yaml`` and the cache is at ``/var/cache/knot-resolver``.

We recommend persistent configuration across container restarts,
for more see `Docker persisting container data <https://docs.docker.com/get-started/docker-concepts/running-containers/persisting-container-data/>`_.

.. code-block:: bash

    $ docker volume create config
    $ docker run --rm -ti --network host -v config:/etc/knot-resolver docker.io/cznic/knot-resolver:6

After a configuration change there is no need to restart the entire container, just tell the resolver to reload the configuration.
Get ``CONTAINER_ID`` using the ``docker ps`` command or give your container name with the ``--name`` argument at container startup.

.. code-block:: bash

    $ docker exec -it CONTANER_ID kresctl reload

.. warning::
    
    Beware of running the container with a software defined network (i.e. in Kubernetes).
    This will likely to result in some performance losses.
    We haven't done any measurements comparing different types of installations so we don't know the performance differences.
    If you have done your own measurements yourself, please contact us and we will share it with everyone else.
