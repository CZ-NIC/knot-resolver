Docker Build
------------

* debian-buster

```
$ export KNOT_BRANCH=3.0
$ docker build --no-cache -t registry.nic.cz/knot/knot-resolver/ci/debian-buster:knot-$KNOT_BRANCH --build-arg KNOT_BRANCH=$KNOT_BRANCH debian-buster

$ docker login registry.nic.cz
$ docker push registry.nic.cz/knot/knot-resolver/ci/debian-buster:knot-$KNOT_BRANCH
```
