Running Knot Resolver under systemd (or equivalent) socket activation
=====================================================================

You can use the files in this directory to run kresd under supervision
by systemd (or any supervisor that provides equivalent file descriptor
initialization via the interface supported by
sd_listen_fds_with_names(3)).

Distributors of systems using systemd may wish to place
./90-kresd.preset in /lib/systemd/systemd-preset/90-kresd.preset if
they want to delay daemon launch until it is accessed. (see
systemd.preset(5)).

When run in this configuration:

 * it will be run under a non-privileged user, which means it will not
   be able to open any new non-privileged ports.

 * it will use a single process (implicitly uses --forks=1, and will
   fail if that configuration variable is set to a different value).
   If you want multiple daemons to listen on these ports publicly
   concurrently, you'll need the supervisor to manage them
   differently, for example via a systemd generator:

     https://www.freedesktop.org/software/systemd/man/systemd.generator.html

   If you have a useful systemd generator for multiple concurrent
   processes, please contribute it upstream!
