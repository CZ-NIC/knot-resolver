#!/usr/bin/python3
"""
Collect systemd-journal log entries around time of daemon exit and coredumps.
"""

import datetime
import json
import logging
import pathlib
import shutil
import subprocess
import sys


TIMESPAN_BEFORE = 600  # s
TIMESPAN_AFTER = TIMESPAN_BEFORE
CURSOR_DIR = pathlib.Path('/var/lib/knot-resolver')
CURSOR_PATH = CURSOR_DIR / 'coredump_watcher.cursor'


class Timestamp:
    def __init__(self, usec):
        self.usec = int(usec)

    @property
    def unix(self):
        return self.usec // 10**6

    def __str__(self):
        return datetime.datetime.utcfromtimestamp(self.unix).strftime('%Y-%m-%d_%H:%M:%S')

    def __lt__(self, other):
        return self.usec < other.usec

    def __eq__(self, other):
        return self.usec == other.usec


class Entry(dict):
    @property
    def timestamp(self):
        usec = self.get('__REALTIME_TIMESTAMP')
        if usec is None:
            return None
        return Timestamp(usec)

    @property
    def core_path(self):
        filename = self.get('COREDUMP_FILENAME')
        if filename is None:
            return None
        return pathlib.Path(filename)

    def get_first(self, *keys):
        for key in keys:
            try:
                return self[key]
            except KeyError:
                continue
        return None

    @property
    def program(self):
        return self.get_first('COREDUMP_UNIT', 'UNIT', '_SYSTEMD_UNIT', 'SYSLOG_IDENTIFIER')

    @property
    def pid(self):
        return self.get_first('COREDUMP_PID', '_PID')


def save_cursor(cursor):
    if cursor is None:
        return
    CURSOR_DIR.mkdir(parents=True, exist_ok=True)
    with CURSOR_PATH.open('w') as curfile:
        curfile.write(cursor)
    logging.info('log cursor saved into %s, next run will skip old logs',
                 CURSOR_PATH)


def load_cursor():
    try:
        with CURSOR_PATH.open('r') as curfile:
            logging.info('log cursor read from %s, skipping old logs',
                         CURSOR_PATH)
            return curfile.read().strip()
    except FileNotFoundError:
        logging.info('log cursor file %s does not exist, parsing all logs',
                     CURSOR_PATH)
        return None


def get_cursor():
    journal_args = ['journalctl', '-o', 'json', '-n', '1']
    with subprocess.Popen(
            journal_args,
            bufsize=1,  # line buffering
            universal_newlines=True,
            stdout=subprocess.PIPE) as jproc:
        stdout, _ = jproc.communicate()
        data = json.loads(stdout)
        entry = Entry(**data)
        return entry.get('__CURSOR')


def read_journal(*args):
    journal_args = [
            'journalctl',
            '-o', 'json',
            '-u', 'kres*',
            '-u', 'systemd-coredump*']
    journal_args += args
    with subprocess.Popen(
            journal_args,
            bufsize=1,  # line buffering
            universal_newlines=True,
            stdout=subprocess.PIPE) as jproc:
        for line in jproc.stdout:
            data = json.loads(line)
            yield Entry(**data)


def extract_logs(around_time, log_name):
    start_time = Timestamp(around_time.usec - TIMESPAN_BEFORE * 10**6)
    end_time = Timestamp(around_time.usec + TIMESPAN_AFTER * 10**6)
    log_window = list(read_journal(
            '--since', '@{}'.format(start_time.unix),
            '--until', '@{}'.format(end_time.unix)))
    with log_name.with_suffix('.json').open('w') as jsonf:
        json.dump(log_window, jsonf, indent=4)
    with log_name.with_suffix('.log').open('w') as logf:
        logf.write('##### logs since {}\n'.format(start_time))
        for entry in log_window:
            if entry.timestamp == around_time:
                logf.write('##### HERE #####\n')
            logf.write('{t} {h} {prg}[{pid}]: {m}\n'.format(
                t=entry.timestamp,
                h=entry.get('_HOSTNAME'),
                prg=entry.program,
                pid=entry.pid,
                m=entry.get('MESSAGE')))
        logf.write('##### logs until {}\n'.format(end_time))


def main():
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 2:
        sys.exit('Usage: {} <output log directory>'.format(sys.argv[0]))
    outdir = pathlib.Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)

    cursor_previous = load_cursor()
    cursor_at_start = get_cursor()

    exit_times = []
    coredumps = {}
    filter_args = []
    if cursor_previous is not None:
        filter_args = ['--after-cursor', cursor_previous]
    for entry in read_journal(*filter_args):
        if 'EXIT_CODE' in entry:
            logging.debug('exit@%s: %s', entry.timestamp, entry)
            exit_times.append(entry.timestamp)
        if 'COREDUMP_FILENAME' in entry:
            logging.debug('coredump @ %s: %s', entry.timestamp, entry.core_path)
            coredumps[entry.core_path] = entry.timestamp

    exit_times.sort()
    logging.debug('detected exits: %s', exit_times)
    for exit_time in exit_times:
        extract_logs(exit_time, outdir / str(exit_time))

    coredumps_missing = 0
    logging.debug('detected coredumps: %s', coredumps)
    for core_path, core_time in coredumps.items():
        core_name = core_path.name
        out_path_prefix = (outdir / str(core_time))
        extract_logs(core_time, out_path_prefix.with_suffix('.logs'))
        try:
            shutil.copy(
                str(core_path),
                str(out_path_prefix.with_suffix('.{}'.format(core_name))))
        except FileNotFoundError as ex:
            logging.error('coredump file %s cannot be copied: %s', core_path, ex)
            coredumps_missing += 1
    logging.info('wrote %d coredumps and %d logs snippets (%s coredumps missing)',
                 len(coredumps) - coredumps_missing, len(exit_times), coredumps_missing)

    save_cursor(cursor_at_start)


if __name__ == '__main__':
    main()
