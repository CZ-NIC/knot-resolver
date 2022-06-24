# type: ignore
# pylint: skip-file

"""
This file is modified version of supervisord's source code:
https://github.com/Supervisor/supervisor/blob/5d9c39619e2e7e7fca33c890cb2a9f2d3d0ab762/supervisor/rpcinterface.py

The changes made are:

 - removed everything that we do not need, reformatted to fit our code stylepo (2022-06-24)
 - made startProcess faster by setting delay to 0 (2022-06-24)


The original supervisord licence follows:
--------------------------------------------------------------------

Supervisor is licensed under the following license:

  A copyright notice accompanies this license document that identifies
  the copyright holders.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1.  Redistributions in source code must retain the accompanying
      copyright notice, this list of conditions, and the following
      disclaimer.

  2.  Redistributions in binary form must reproduce the accompanying
      copyright notice, this list of conditions, and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

  3.  Names of the copyright holders must not be used to endorse or
      promote products derived from this software without prior
      written permission from the copyright holders.

  4.  If any files are modified, you must cause the modified files to
      carry prominent notices stating that you changed the files and
      the date of any change.

  Disclaimer

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND
    ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
    TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
    PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
    HOLDERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
    TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
    ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
    TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
    THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.
"""

from supervisor.http import NOT_DONE_YET
from supervisor.options import BadCommand, NoPermission, NotExecutable, NotFound, split_namespec
from supervisor.states import RUNNING_STATES, ProcessStates, SupervisorStates
from supervisor.xmlrpc import Faults, RPCError


class SupervisorNamespaceRPCInterface:
    def __init__(self, supervisord):
        self.supervisord = supervisord

    def _update(self, text):
        self.update_text = text  # for unit tests, mainly
        if isinstance(self.supervisord.options.mood, int) and self.supervisord.options.mood < SupervisorStates.RUNNING:
            raise RPCError(Faults.SHUTDOWN_STATE)

    # RPC API methods

    def _getGroupAndProcess(self, name):
        # get process to start from name
        group_name, process_name = split_namespec(name)

        group = self.supervisord.process_groups.get(group_name)
        if group is None:
            raise RPCError(Faults.BAD_NAME, name)

        if process_name is None:
            return group, None

        process = group.processes.get(process_name)
        if process is None:
            raise RPCError(Faults.BAD_NAME, name)

        return group, process

    def startProcess(self, name, wait=True):
        """Start a process

        @param string name Process name (or ``group:name``, or ``group:*``)
        @param boolean wait Wait for process to be fully started
        @return boolean result     Always true unless error

        """
        self._update("startProcess")
        group, process = self._getGroupAndProcess(name)
        if process is None:
            group_name, process_name = split_namespec(name)
            return self.startProcessGroup(group_name, wait)

        # test filespec, don't bother trying to spawn if we know it will
        # eventually fail
        try:
            filename, argv = process.get_execv_args()
        except NotFound as why:
            raise RPCError(Faults.NO_FILE, why.args[0])
        except (BadCommand, NotExecutable, NoPermission) as why:
            raise RPCError(Faults.NOT_EXECUTABLE, why.args[0])

        if process.get_state() in RUNNING_STATES:
            raise RPCError(Faults.ALREADY_STARTED, name)

        if process.get_state() == ProcessStates.UNKNOWN:
            raise RPCError(Faults.FAILED, "%s is in an unknown process state" % name)

        process.spawn()

        # We call reap() in order to more quickly obtain the side effects of
        # process.finish(), which reap() eventually ends up calling.  This
        # might be the case if the spawn() was successful but then the process
        # died before its startsecs elapsed or it exited with an unexpected
        # exit code. In particular, finish() may set spawnerr, which we can
        # check and immediately raise an RPCError, avoiding the need to
        # defer by returning a callback.

        self.supervisord.reap()

        if process.spawnerr:
            raise RPCError(Faults.SPAWN_ERROR, name)

        # We call process.transition() in order to more quickly obtain its
        # side effects.  In particular, it might set the process' state from
        # STARTING->RUNNING if the process has a startsecs==0.
        process.transition()

        if wait and process.get_state() != ProcessStates.RUNNING:
            # by default, this branch will almost always be hit for processes
            # with default startsecs configurations, because the default number
            # of startsecs for a process is "1", and the process will not have
            # entered the RUNNING state yet even though we've called
            # transition() on it.  This is because a process is not considered
            # RUNNING until it has stayed up > startsecs.

            def onwait():
                if process.spawnerr:
                    raise RPCError(Faults.SPAWN_ERROR, name)

                state = process.get_state()

                if state not in (ProcessStates.STARTING, ProcessStates.RUNNING):
                    raise RPCError(Faults.ABNORMAL_TERMINATION, name)

                if state == ProcessStates.RUNNING:
                    return True

                return NOT_DONE_YET

            onwait.delay = 0
            onwait.rpcinterface = self
            return onwait  # deferred

        return True


# this is not used in code but referenced via an entry point in the conf file
def make_main_rpcinterface(supervisord):
    return SupervisorNamespaceRPCInterface(supervisord)
