#!/usr/bin/python3
"""
Generate RFC 5011 test simulating successful KSK roll-over in 2017.

Dependencies: Knot DNS server + Deckard library.
Environment: Set PYTHONPATH variable so "import pydnstest" will use module from Deckard.
Input: Root zone files, presumably created by genkeyszones.sh.
Output: RPL file for Deckard on standard output.
"""

import copy
import datetime
import os.path
import subprocess
import time

import dns.resolver

import pydnstest.scenario

try:
    VARIANT = os.environ["VARIANT"]
except KeyError:
    VARIANT = ""

def store_answer(qname, qtype, template):
    answ = dns.resolver.query(qname, qtype, raise_on_no_answer=False)
    entr = copy.copy(template)
    entr.message = answ.response
    return entr


def resolver_init():
    """
    Configure dns.resolver to ask ::1@5353 with EDNS0 DO set.
    """
    dns.resolver.reset_default_resolver()
    dns.resolver.default_resolver.use_edns(0, dns.flags.DO, 4096)
    dns.resolver.default_resolver.nameservers = ['::1']
    dns.resolver.default_resolver.nameserver_ports = {'::1': 5353}
    dns.resolver.default_resolver.flags = 0


def get_templates():
    """
    Return empty objects for RANGE and ENTRY suitable as object templates.
    """
    empty_case, _ = pydnstest.scenario.parse_file(os.path.realpath('empty.rpl'))

    rng = copy.copy(empty_case.ranges[0])

    entry = copy.copy(rng.stored[0])
    entry.adjust_fields = ['copy_id']
    entry.match_fields = ['opcode', 'question']

    rng.addresses = {'198.41.0.4', '2001:503:ba3e::2:30'}
    rng.stored = []

    return rng, entry


def generate_range(filename, rng_templ, entry_templ):
    """
    Run Knot DNS server with specified zone file and generate RANGE object.
    """
    assert filename.startswith('20')
    assert filename.endswith('.db')
    try:
        os.unlink('root.db')
    except FileNotFoundError:
        pass
    os.link(filename, 'root.db')

    # run server
    knotd = subprocess.Popen(['knotd', '-c', 'knot.root.conf', '-s', '/tmp/knot-dns2rpl.sock'])
    time.sleep(0.1)  # give kresd time to start so we do not wait for first timeout

    # query data
    rng = copy.copy(rng_templ)
    rng.stored = []
    rng.stored.append(store_answer('.', 'SOA', entry_templ))
    rng.stored.append(store_answer('.', 'DNSKEY', entry_templ))
    rng.stored.append(store_answer('.', 'NS', entry_templ))
    rng.stored.append(store_answer('rootns.', 'NS', entry_templ))
    rng.stored.append(store_answer('rootns.', 'A', entry_templ))
    rng.stored.append(store_answer('rootns.', 'AAAA', entry_templ))
    rng.stored.append(store_answer('test.', 'TXT', entry_templ))
    rng.a = int(filename[:-len('.db')])

    # kill server
    knotd.kill()

    return rng


def generate_step_query(tcurr, id_prefix):
    out = '; {0}'.format(tcurr.isoformat())
    out += '''
STEP {0}000000 QUERY
ENTRY_BEGIN
REPLY RD AD
SECTION QUESTION
test. IN TXT
ENTRY_END
'''.format(id_prefix)
    return out


def generate_step_check(id_prefix):
    return '''STEP {0}000001 CHECK_ANSWER
ENTRY_BEGIN
REPLY QR RD RA AD
MATCH opcode rcode flags question answer
SECTION QUESTION
test. IN TXT
SECTION ANSWER
test. IN TXT "it works"
ENTRY_END
'''.format(id_prefix)

def generate_step_nocheck(id_prefix):
    return '''STEP {0}000001 CHECK_ANSWER
ENTRY_BEGIN
REPLY QR RD RA AD
MATCH opcode qname question
SECTION QUESTION
test. IN TXT
SECTION ANSWER
test. IN TXT "it works"
ENTRY_END
'''.format(id_prefix)

def generate_step_finish_msg(id_prefix):
    return '''STEP {0}000001 CHECK_ANSWER
ENTRY_BEGIN
REPLY QR RD RA AA NXDOMAIN
MATCH opcode rcode flags question answer
SECTION QUESTION
test. IN TXT
SECTION AUTHORITY
test. 10800 IN SOA test. nobody.invalid. 1 3600 1200 604800 10800
SECTION ADDITIONAL
explanation.invalid. 10800 IN TXT "check last answer"
ENTRY_END
'''.format(id_prefix)

def generate_step_elapse(tstep, id_prefix):
    out = '; move time by {0}\n'.format(tstep)
    out += '''STEP {0}000099 TIME_PASSES ELAPSE {1}\n\n'''.format(
        id_prefix, int(tstep.total_seconds()))
    return out


def main():
    resolver_init()
    rng_templ, entry_templ = get_templates()
    ranges = []
    check_last_msg = False

    # transform data in zones files into RANGEs
    files = os.listdir()
    files.sort()
    for fn in files:
        if not fn.endswith('.db') or not fn.startswith('20'):
            continue
        ranges.append(generate_range(fn, rng_templ, entry_templ))

    # connect ranges
    for i in range(1, len(ranges)):
        ranges[i - 1].b = ranges[i].a - 1
    ranges[-1].b = 99999999999999

    # steps
    steps = []
    tstart = datetime.datetime(year=2017, month=7, day=1)
    if VARIANT == "unmanaged_key":
        tend = datetime.datetime(year=2017, month=7, day=21, hour=23, minute=59, second=59)
        check_last_msg = True
    else:
        tend = datetime.datetime(year=2017, month=12, day=31, hour=23, minute=59, second=59)
    tstep = datetime.timedelta(days=1)
    tcurr = tstart
    while tcurr < tend:
        id_prefix = tcurr.strftime('%Y%m%d')
        steps.append(generate_step_query(tcurr, id_prefix))
        if (check_last_msg is True and tcurr + tstep > tend):
            steps.append(generate_step_finish_msg(id_prefix))
        elif VARIANT == "unmanaged_key":
            steps.append(generate_step_nocheck(id_prefix))
        else:
            steps.append(generate_step_check(id_prefix))
        steps.append(generate_step_elapse(tstep, id_prefix))
        tcurr += tstep

    # generate output
    with open('keys/ds') as dsfile:
        tas = dsfile.read().strip()

    # constant RPL file header
    print("stub-addr: 2001:503:ba3e::2:30")
    for ta in tas.split('\n'):
        print ("trust-anchor: " + ta)
    print("""val-override-date: 20170701000000
query-minimization: off
CONFIG_END

SCENARIO_BEGIN Simulation of successful RFC 5011 KSK roll-over during 2017
    """.format(ta=ta))
    for rng in ranges:
        print(rng)

    for step in steps:
        print(step)

    # constant RPL file footer
    print('''
SCENARIO_END
    ''')


if __name__ == '__main__':
    main()
