#!/usr/bin/env python
import sys
import os
import fileinput
import subprocess
import tempfile
import shutil
import socket
import time
import signal
import stat
from pydnstest import scenario, testserver, test
from datetime import datetime

# Test debugging
TEST_DEBUG = 0
if 'TEST_DEBUG' in os.environ:
    TEST_DEBUG = int(os.environ['TEST_DEBUG'])

def del_files(path_to):
    for root, dirs, files in os.walk(path_to):
        for f in files:
            os.unlink(os.path.join(root, f))

DEFAULT_IFACE = 0
CHILD_IFACE = 0
TMPDIR = ""
if "SOCKET_WRAPPER_DEFAULT_IFACE" in os.environ:
   DEFAULT_IFACE = int(os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"])
if DEFAULT_IFACE < 2 or DEFAULT_IFACE > 254 :
    if TEST_DEBUG > 0:
        testserver.syn_print(None,"SOCKET_WRAPPER_DEFAULT_IFACE is invalid ({}), set to default (10)".format(DEFAULT_IFACE))
    DEFAULT_IFACE = 10
    os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"]="{}".format(DEFAULT_IFACE)
if "KRESD_WRAPPER_DEFAULT_IFACE" in os.environ:
    CHILD_IFACE = int(os.environ["KRESD_WRAPPER_DEFAULT_IFACE"])
if CHILD_IFACE < 2 or CHILD_IFACE > 254 or CHILD_IFACE == DEFAULT_IFACE:
    if TEST_DEBUG > 0:
        testserver.syn_print(None,"KRESD_WRAPPER_DEFAULT_IFACE is invalid ({}), set to default ({})".format(CHILD_IFACE, DEFAULT_IFACE + 1))
    CHILD_IFACE = DEFAULT_IFACE + 1
    if CHILD_IFACE > 254:
        CHILD_IFACE = 2
if "SOCKET_WRAPPER_DIR" in os.environ:
    TMPDIR = os.environ["SOCKET_WRAPPER_DIR"]
if TMPDIR == "" or os.path.isdir(TMPDIR) is False:
    OLDTMPDIR = TMPDIR
    TMPDIR = tempfile.mkdtemp(suffix='', prefix='tmp')
#    os.chmod(TMPDIR,stat.S_IRUSR|stat.S_IWUSR|stat.S_IXUSR|stat.S_IRGRP|stat.S_IWGRP|stat.S_IXGRP|stat.S_IROTH|stat.S_IWOTH|stat.S_IXOTH)
    os.environ["SOCKET_WRAPPER_DIR"] = TMPDIR
    if TEST_DEBUG > 0:
        testserver.syn_print(None,"SOCKET_WRAPPER_DIR is invalid or empty ({}), set to default ({})".format(OLDTMPDIR, TMPDIR))
if TEST_DEBUG > 0:
    testserver.syn_print(None,"default_iface: {}, child_iface: {}, tmpdir {}".format(DEFAULT_IFACE, CHILD_IFACE, TMPDIR))
del_files(TMPDIR)

# Set up libfaketime
os.environ["FAKETIME_NO_CACHE"] = "1"
os.environ["FAKETIME_TIMESTAMP_FILE"] = '%s/.time' % TMPDIR
time_file = open(os.environ["FAKETIME_TIMESTAMP_FILE"], 'w')
time_file.write(datetime.fromtimestamp(0).strftime('%Y-%m-%d %H:%M:%S'))
time_file.close()

def get_next(file_in):
    """ Return next token from the input stream. """
    while True:
        line = file_in.readline()
        if len(line) == 0:
            return False
        for csep in (';', '#'):
            if csep in line:
                line = line[0:line.index(csep)]
        tokens = ' '.join(line.strip().split()).split()
        if len(tokens) == 0:
            continue  # Skip empty lines
        op = tokens.pop(0)
        return op, tokens


def parse_entry(op, args, file_in):
    """ Parse entry definition. """
    out = scenario.Entry()
    for op, args in iter(lambda: get_next(file_in), False):
        if op == 'ENTRY_END':
            break
        elif op == 'REPLY':
            out.set_reply(args)
        elif op == 'MATCH':
            out.set_match(args)
        elif op == 'ADJUST':
            out.set_adjust(args)
        elif op == 'SECTION':
            out.begin_section(args[0])
        elif op == 'RAW':
            out.begin_raw()
        else:
            out.add_record(op, args)
    return out


def parse_step(op, args, file_in):
    """ Parse range definition. """
    if len(args) < 2:
        raise Exception('expected STEP <id> <type>')
    extra_args = []
    if len(args) > 2:
        extra_args = args[2:]
    out = scenario.Step(args[0], args[1], extra_args)
    if out.has_data:
        op, args = get_next(file_in)
        if op == 'ENTRY_BEGIN':
            out.add(parse_entry(op, args, file_in))
        else:
            raise Exception('expected "ENTRY_BEGIN"')
    return out


def parse_range(op, args, file_in):
    """ Parse range definition. """
    if len(args) < 2:
        raise Exception('expected RANGE_BEGIN <from> <to>')
    out = scenario.Range(int(args[0]), int(args[1]))
    for op, args in iter(lambda: get_next(file_in), False):
        if op == 'ADDRESS':
            out.address = args[0]
        elif op == 'ENTRY_BEGIN':
            out.add(parse_entry(op, args, file_in))
        elif op == 'RANGE_END':
            break
    return out


def parse_scenario(op, args, file_in):
    """ Parse scenario definition. """
    out = scenario.Scenario(args[0])
    for op, args in iter(lambda: get_next(file_in), False):
        if op == 'SCENARIO_END':
            break
        if op == 'RANGE_BEGIN':
            out.ranges.append(parse_range(op, args, file_in))
        if op == 'STEP':
            out.steps.append(parse_step(op, args, file_in))
    return out


def parse_file(file_in):
    """ Parse scenario from a file. """
    try:
        config = ''
        line = file_in.readline()
        while len(line):
            if line.startswith('CONFIG_END'):
                break
            if not line.startswith(';'):
                config += line
            line = file_in.readline()
        for op, args in iter(lambda: get_next(file_in), False):
            if op == 'SCENARIO_BEGIN':
                return parse_scenario(op, args, file_in), config
        raise Exception("IGNORE (missing scenario)")
    except Exception as e:
        raise Exception('line %d: %s' % (file_in.lineno(), str(e)))


def find_objects(path):
    """ Recursively scan file/directory for scenarios. """
    result = []
    if os.path.isdir(path):
        for e in os.listdir(path):
            result += find_objects(os.path.join(path, e))
    elif os.path.isfile(path):
        if path.endswith('.rpl'):
            result.append(path)
    return result


def play_object(path):
    """ Play scenario from a file object. """

    # Parse scenario
    file_in = fileinput.input(path)
    scenario = None
    config = None
    try:
        scenario, config = parse_file(file_in)
    finally:
        file_in.close()

    child_env = os.environ.copy()
    child_env["SOCKET_WRAPPER_DEFAULT_IFACE"] = "%i" % CHILD_IFACE
    child_env["SOCKET_WRAPPER_DIR"] = TMPDIR
    selfaddr = testserver.get_local_addr_str(socket.AF_INET,DEFAULT_IFACE)
    childaddr = testserver.get_local_addr_str(socket.AF_INET,CHILD_IFACE)
    fd = os.open( TMPDIR + "/config", os.O_RDWR|os.O_CREAT )
    os.write(fd, "net.listen('{}',53)\n".format(childaddr) )
    os.write(fd, "modules = {'hints'}\n")
    os.write(fd, "hints.root({['k.root-servers.net'] = '%s'})\n" % selfaddr)
    os.close(fd)


    # !!! ATTENTION !!!
    # cwrapped kresd constantly fails at startup with empty SOCKET_WRAPPER_DIR
    # race condition?
    # workaround - check output and try to restart if fails
    # also, wait for subprocess starts
    fails = False
    binary = subprocess.Popen(["./daemon/kresd",TMPDIR], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, env=child_env)
    while binary.poll() is None:
        line = binary.stdout.readline()
        if line.find("[system] quitting") != -1:
            fails = True
            binary.wait()
            break
        elif line.find("[hint] loaded") != -1:
            break

    if fails or binary.poll() is not None: #second attempt
        fails = False
        binary = subprocess.Popen(["./daemon/kresd",TMPDIR], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, env=child_env)
        while binary.poll() is None:
            line = binary.stdout.readline()
            if line.find("[system] quitting") != -1:
                fails = True
                binary.wait()
                break
            elif line.find("[hint] loaded") != -1:
                break
    
    if fails or binary.poll() is not None :
        raise Exception("Can't start kresd")

    # Play scenario
    server = testserver.TestServer(scenario, config, DEFAULT_IFACE, CHILD_IFACE)
    server.start()
    try:
        if TEST_DEBUG > 0:
            testserver.syn_print('--- UDP test server started at')
            testserver.syn_print(server.address())
            testserver.syn_print('--- scenario parsed, any key to continue ---')
        server.play()
    finally:
        server.stop()
        os.killpg(binary.pid, signal.SIGTERM)
        del_files(TMPDIR)
    subprocess.call(["pkill","kresd"])

def test_platform(*args):
    if sys.platform == 'windows':
        raise Exception('not supported at all on Windows')

if __name__ == '__main__':

    # Self-tests first
    test = test.Test()
    test.add('integration/platform', test_platform)
    test.add('testserver/sendrecv', testserver.test_sendrecv, DEFAULT_IFACE, DEFAULT_IFACE)
    if test.run() != 0:
        sys.exit(1)
    else:
        # Scan for scenarios
        for arg in sys.argv[1:]:
            objects = find_objects(arg)
            for path in objects:
                test.add(path, play_object, path)
        sys.exit(test.run())
