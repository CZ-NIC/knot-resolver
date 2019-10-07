Docker Build
------------

* debian-buster

```
$ export KNOT_BRANCH=2.8
$ docker build --no-cache -t registry.labs.nic.cz/knot/knot-resolver/ci/debian-buster:knot-$KNOT_BRANCH --build-arg KNOT_BRANCH=$KNOT_BRANCH debian-buster

$ docker login registry.labs.nic.cz
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/debian-buster:knot-$KNOT_BRANCH
```

* turris

```
$ docker build --no-cache -t registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia turris
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia
```

Alternatively, provide `SDK_REPO` build arg (dir name from https://repo.turris.cz/ )

```
$ docker build --no-cache --build-arg SDK_REPO=omnia-nightly -t registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia-nightly turris
$ docker push registry.labs.nic.cz/knot/knot-resolver/ci/turris:omnia-nightly
```
