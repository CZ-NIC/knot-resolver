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
import errno
import jinja2
from pydnstest import scenario, testserver, test
from datetime import datetime

def str2bool(v):
    """ Return conversion of JSON-ish string value to boolean. """ 
    return v.lower() in ('yes', 'true', 'on')

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
    DEFAULT_IFACE = 10
    os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"]="{}".format(DEFAULT_IFACE)

if "KRESD_WRAPPER_DEFAULT_IFACE" in os.environ:
    CHILD_IFACE = int(os.environ["KRESD_WRAPPER_DEFAULT_IFACE"])
if CHILD_IFACE < 2 or CHILD_IFACE > 254 or CHILD_IFACE == DEFAULT_IFACE:
    OLD_CHILD_IFACE = CHILD_IFACE
    CHILD_IFACE = DEFAULT_IFACE + 1
    if CHILD_IFACE > 254:
        CHILD_IFACE = 2
    os.environ["KRESD_WRAPPER_DEFAULT_IFACE"] = "{}".format(CHILD_IFACE)

if "SOCKET_WRAPPER_DIR" in os.environ:
    TMPDIR = os.environ["SOCKET_WRAPPER_DIR"]
if TMPDIR == "" or os.path.isdir(TMPDIR) is False:
    OLDTMPDIR = TMPDIR
    TMPDIR = tempfile.mkdtemp(suffix='', prefix='tmp')
    os.environ["SOCKET_WRAPPER_DIR"] = TMPDIR

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
        config = []
        line = file_in.readline()
        while len(line):
            if line.startswith('CONFIG_END'):
                break
            if not line.startswith(';'):
                if '#' in line:
                    line = line[0:line.index('#')]
                # Break to key-value pairs
                # e.g.: ['minimization', 'on']
                kv = [x.strip() for x in line.split(':')]
                if len(kv) >= 2:
                    config.append(kv)
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

def write_timestamp_file(path, tst):
    time_file = open(path, 'w')
    time_file.write(datetime.fromtimestamp(tst).strftime('%Y-%m-%d %H:%M:%S'))
    time_file.close()

def setup_env(child_env, config, config_name, j2template):
    """ Set up test environment and config """
    # Clear test directory
    del_files(TMPDIR)
    # Set up libfaketime
    os.environ["FAKETIME_NO_CACHE"] = "1"
    os.environ["FAKETIME_TIMESTAMP_FILE"] = '%s/.time' % TMPDIR
    child_env["FAKETIME_NO_CACHE"] = "1"
    child_env["FAKETIME_TIMESTAMP_FILE"] = '%s/.time' % TMPDIR
    write_timestamp_file(child_env["FAKETIME_TIMESTAMP_FILE"], 0)
    # Set up child process env() 
    child_env["SOCKET_WRAPPER_DEFAULT_IFACE"] = "%i" % CHILD_IFACE
    child_env["SOCKET_WRAPPER_DIR"] = TMPDIR
    no_minimize = "true"
    trust_anchor_str = ""
    stub_addr = ""
    for k,v in config:
        # Enable selectively for some tests
        if k == 'query-minimization' and str2bool(v):
            no_minimize = "false"
        elif k == 'trust-anchor':
            trust_anchor_str = v.strip('"\'')
        elif k == 'val-override-date':
            override_date_str = v.strip('"\'')
            write_timestamp_file(child_env["FAKETIME_TIMESTAMP_FILE"], int(override_date_str))
        elif k == 'stub-addr':
            stub_addr = v.strip('"\'')
    if stub_addr.startswith('127.0.0.') or stub_addr.startswith('::'):
        selfaddr = stub_addr
    else:
        selfaddr = testserver.get_local_addr_str(socket.AF_INET, DEFAULT_IFACE)
    childaddr = testserver.get_local_addr_str(socket.AF_INET, CHILD_IFACE)
    # Prebind to sockets to create necessary files
    # @TODO: this is probably a workaround for socket_wrapper bug
    for sock_type in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((childaddr, 53))
        if sock_type == socket.SOCK_STREAM:
            sock.listen(5)
    # Generate configuration
    j2template_ctx = {
        "ROOT_ADDR" : selfaddr,
        "SELF_ADDR" : childaddr,
        "NO_MINIMIZE" : no_minimize,
        "TRUST_ANCHOR" : trust_anchor_str,
        "WORKING_DIR" : TMPDIR,
    }
    cfg_rendered = j2template.render(j2template_ctx)
    f = open(os.path.join(TMPDIR,config_name), 'w')
    f.write(cfg_rendered)
    f.close()

def play_object(path, binary_name, config_name, j2template, binary_additional_pars):
    """ Play scenario from a file object. """

    # Parse scenario
    file_in = fileinput.input(path)
    scenario = None
    config = None
    try:
        scenario, config = parse_file(file_in)
    finally:
        file_in.close()

    # Setup daemon environment
    daemon_env = os.environ.copy()
    setup_env(daemon_env, config, config_name, j2template)
    # Start binary
    daemon_proc = None
    daemon_log = open('%s/server.log' % TMPDIR, 'w')
    daemon_args = [binary_name] + binary_additional_pars
    try :
      daemon_proc = subprocess.Popen(daemon_args, stdout=daemon_log, stderr=daemon_log,
                                     cwd=TMPDIR, preexec_fn=os.setsid, env=daemon_env)
    except Exception as e:
        raise Exception("Can't start '%s': %s" % (daemon_args, str(e)))
    # Wait until the server accepts TCP clients
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
    	time.sleep(0.1)
        if daemon_proc.poll() != None:
            print(open('%s/server.log' % TMPDIR).read())
            raise Exception('process died "%s", logs in "%s"' % (os.path.basename(binary_name), TMPDIR))
        try:
            sock.connect((testserver.get_local_addr_str(socket.AF_INET, CHILD_IFACE), 53))
        except: continue
        break
    # Play scenario
    server = testserver.TestServer(scenario, config, DEFAULT_IFACE, CHILD_IFACE)
    server.start()
    try:
        server.play()
    finally:
        server.stop()
        daemon_proc.terminate()
        daemon_proc.wait()
        if 'VERBOSE' in os.environ:
            print('[ LOG      ]\n%s' % open('%s/server.log' % TMPDIR).read())
    # Do not clear files if the server crashed (for analysis)
    del_files(TMPDIR)

def test_platform(*args):
    if sys.platform == 'windows':
        raise Exception('not supported at all on Windows')

if __name__ == '__main__':

    if len(sys.argv) < 5:
        print "Usage: test_integration.py <scenario> <binary> <template> <config name> [<additional>]"
        print "\t<scenario> - path to scenario"
        print "\t<binary> - executable to test"
        print "\t<template> - jinja2 template file to generate configuration"
        print "\t<config name> - name of configuration file to be generated"
        print "\t<additional> - additional parameters for <binary>"
        sys.exit(0)

    test_platform()
    path_to_scenario = ""
    binary_name = ""
    template_name = ""
    config_name = ""
    binary_additional_pars = []

    if len(sys.argv) > 4:
        path_to_scenario = sys.argv[1]
        binary_name = sys.argv[2]
        template_name = sys.argv[3]
        config_name = sys.argv[4]

    if len(sys.argv) > 5:
        binary_additional_pars = sys.argv[5:]

    j2template_loader = jinja2.FileSystemLoader(searchpath=os.path.dirname(os.path.abspath(__file__)))
    j2template_env = jinja2.Environment(loader=j2template_loader)
    j2template = j2template_env.get_template(template_name)

    # Scan for scenarios
    test = test.Test()
    for arg in [path_to_scenario]:
        objects = find_objects(arg)
        for path in objects:
            test.add(path, play_object, path, binary_name, config_name, j2template, binary_additional_pars)
    sys.exit(test.run())
