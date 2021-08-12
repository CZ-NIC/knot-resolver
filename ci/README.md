Docker Build
------------

```
$ export DISTRO=debian-buster # also debian-11
$ export KNOT_BRANCH=3.0 # also master
$ docker build --no-cache -t registry.nic.cz/knot/knot-resolver/ci/$DISTRO:knot-$KNOT_BRANCH --build-arg KNOT_BRANCH=$KNOT_BRANCH $DISTRO

$ docker login registry.nic.cz
$ docker push registry.nic.cz/knot/knot-resolver/ci/$DISTRO:knot-$KNOT_BRANCH
```
