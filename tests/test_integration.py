#!/usr/bin/env python
import sys, os, fileinput
from pydnstest import scenario, testserver
import _test_integration as mock_ctx

# Test debugging
TEST_DEBUG = 0
if 'TEST_DEBUG' in os.environ:
    TEST_DEBUG = int(os.environ['TEST_DEBUG'])


def get_next(file_in):
    """ Return next token from the input stream. """
    while True:
        line = file_in.readline()
        if len(line) == 0:
            return False
        tokens = ' '.join(line.strip().split()).split()
        if len(tokens) == 0:
            continue  # Skip empty lines
        op = tokens.pop(0)
        if op.startswith(';') or op.startswith('#'):
            continue  # Skip comments
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
    op, args = get_next(file_in)
    # Optional data
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
        for op, args in iter(lambda: get_next(file_in), False):
            if op == 'SCENARIO_BEGIN':
                return parse_scenario(op, args, file_in)
        raise Exception("IGNORE (missing scenario)")
    except Exception as e:
        raise Exception('line %d: %s' % (file_in.lineno(), str(e)))


def parse_object(path):
    """ Recursively scan file/directory for scenarios. """
    if os.path.isdir(path):
        for e in os.listdir(path):
            parse_object(os.path.join(path, e))
    elif os.path.isfile(path):
        play_object(path)


def play_object(path):
    """ Play scenario from a file object. """

    # Parse scenario
    file_in = fileinput.input(path)
    scenario = None
    try:
        scenario = parse_file(file_in)
    except Exception as e:
        print('%s %s' % (os.path.basename(path), str(e)))
    file_in.close()
    if scenario is None:
        return

    # Play scenario
    server = testserver.TestServer(scenario)
    server.start()
    mock_ctx.init()
    mock_ctx.set_server(server)
    try:
        if TEST_DEBUG > 0:
            print('--- server listening at %s ---' % str(server.server.server_address))
            print('--- scenario parsed, any key to continue ---')
            sys.stdin.readline()
        scenario.play(mock_ctx)
        print('%s OK' % os.path.basename(path))
    except Exception as e:
        print('%s %s' % (os.path.basename(path), str(e)))
    finally:
        server.stop()
        mock_ctx.deinit()


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        parse_object(arg)
