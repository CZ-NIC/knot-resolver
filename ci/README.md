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

* turris

```
$ docker build -t registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia turris
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia
```

Alternatively, provide `SDK_REPO` build arg (dir name from https://repo.turris.cz/ )

```
$ docker build --build-arg SDK_REPO=omnia-nightly -t registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia-nightly turris
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia-nightly
```
