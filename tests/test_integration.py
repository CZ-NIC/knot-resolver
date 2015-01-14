#!/usr/bin/env python
import sys, os, fileinput
import _test_integration


def parse_entry(line, file_in):
    """ Parse entry definition. """
    print line.split(' ')
    for line in iter(lambda: file_in.readline(), ''):
        if line.startswith('ENTRY_END'):
            break


def parse_step(line, file_in):
    """ Parse range definition. """
    print line.split(' ')


def parse_range(line, file_in):
    """ Parse range definition. """
    print line.split(' ')
    for line in iter(lambda: file_in.readline(), ''):
        if line.startswith('ENTRY_BEGIN'):
            parse_entry(line, file_in)
        if line.startswith('RANGE_END'):
            break


def parse_scenario(line, file_in):
    """ Parse scenario definition. """
    print line.split(' ')
    for line in iter(lambda: file_in.readline(), ''):
        if line.startswith('SCENARIO_END'):
            break
        if line.startswith('RANGE_BEGIN'):
            parse_range(line, file_in)
        if line.startswith('STEP'):
            parse_step(line, file_in)


def parse_file(file_in):
    """ Parse and play scenario from a file. """
    try:
        for line in iter(lambda: file_in.readline(), ''):
            if line.startswith('SCENARIO_BEGIN'):
                return parse_scenario(line, file_in)
        raise Exception("IGNORE (missing scenario)")
    except Exception as e:
        raise Exception('line %d: %s' % (file_in.lineno(), str(e)))


def parse_object(path):
    """ Recursively scan file/directory for scenarios. """
    if os.path.isdir(path):
        for e in os.listdir(path):
            parse_object(os.path.join(path, e))
    elif os.path.isfile(path):
        file_in = fileinput.input(path)
        try:
            parse_file(file_in)
            print('%s OK' % os.path.basename(path))
        except Exception as e:
            print('%s %s' % (os.path.basename(path), str(e)))
        file_in.close()


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        parse_object(arg)
