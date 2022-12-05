.. SPDX-License-Identifier: GPL-3.0-or-later

With the release of version 6, there is a new way to configure and control your running ``kresd`` instances
so that you don't have to configure multiple systemd services. The new Knot Resolver Manager handles it for you.
In the table below, you can find comparison of how things were done before and how they can be done now.

======================
Administration changes
======================

==========================================  ===========================================================================================  ==================================================================
Task                                        How to do it now                                                                             How it was done before           
==========================================  ===========================================================================================  ==================================================================
start resolver                              ``systemctl start knot-resolver``                                                            ``systemctl start kresd@1``
stop resolver                               ``systemctl stop knot-resolver``                                                             ``systemctl stop kresd@1``
start resolver with 4 worker processes      set ``/workers`` to 4 in the config file                                                     manually start 4 services by ``systemctl start kresd@{1,2,3,4}``
rolling restart after updating config       ``systemctl reload knot-resolver`` (or use API or ``kresctl``)                               manually restart individual ``kresd@`` services one by one
open logs of all instances                  ``journalctl -u knot-resolver``                                                              ``journalctl -u system-kresd.slice``
open log of a single kresd instances        ``journalctl -u knot-resolver _PID=xxx``                                                     ``journalctl -u kresd@1``
updating config programatically             use HTTP API or ``kresctl`` command                                                          write a custom tool to generate new config and restart ``kresd``'s
handling errors during config changes       HTTP API just reports error, resolver keeps running with previous config                     custom tools for every user
validate new config                         ``kresctl validate path/to/new/config.yml`` (not fully bullet proof), then try to run it     run ``kresd`` with the config and see if it fails
look at the Lua config                      ``kresctl convert path/to/new/config.yml``                                                   ``cat /path/to/config.conf``
gather metrics                              point Prometheus etc. at the single HTTP API                                                 collect metrics manually from all individual processes
==========================================  ===========================================================================================  ==================================================================
