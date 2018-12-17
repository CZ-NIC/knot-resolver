Docker Build
------------

* debian-stable / debian-unstable

```
$ export KNOT_BRANCH=2.7
$ docker build -t registry.labs.nic.cz/knot/knot-resolver/ci/debian-stable:knot-$KNOT_BRANCH --build-arg KNOT_BRANCH=$KNOT_BRANCH debian-stable
$ docker build -t registry.labs.nic.cz/knot/knot-resolver/ci/debian-unstable:knot-$KNOT_BRANCH --build-arg KNOT_BRANCH=$KNOT_BRANCH debian-unstable

$ docker login registry.labs.nic.cz
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/debian-stable:knot-$KNOT_BRANCH
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/debian-unstable:knot-$KNOT_BRANCH
```

* fedora

```
$ docker build -t registry.labs.nic.cz/knot/knot-resolver/ci/fedora fedora
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/fedora
```
