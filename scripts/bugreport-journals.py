#!/usr/bin/python3
"""
Collect sysmted-journald log entries around time of daemon exit and coredumps.
"""

import datetime
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys


TIMESPAN_BEFORE = 600  # s
TIMESPAN_AFTER = TIMESPAN_BEFORE


class Cursors:
    cursordir = pathlib.Path('/var/lib/knot-resolver')
    path = cursordir / pathlib.Path('coredump_watcher.cursor')

    @staticmethod
    def overwrite_previous(new_cursor):
        logging.info('log cursor saved into %s, next run will skip old logs',
                     Cursors.path)
        Cursors.cursordir.mkdir(parents=True, exist_ok=True)
        with Cursors.path.open('w') as curfile:
            curfile.write(new_cursor)

    @staticmethod
    def get_previous():
        try:
            with Cursors.path.open('r') as curfile:
                logging.info('log cursor read from %s, skipping old logs',
                             Cursors.path)
                return curfile.read().strip()
        except FileNotFoundError:
            logging.info('log cursor file %s does not exist, parsing all logs',
                         Cursors.path)
            return None

    @staticmethod
    def get_current():
        journal_args = ['journalctl', '-o', 'json', '-n', '1']
        with subprocess.Popen(journal_args,
                bufsize=1,  # line buffering
                universal_newlines=True,
                stdout=subprocess.PIPE) as jproc:
            stdout, _ = jproc.communicate()
            entry = json.loads(stdout)
            return entry['__CURSOR']


class Timestamps:
    @staticmethod
    def str2unix(string):
        # systemd uses microsecond resolution
        return int(string) / 10**6

    def unix2print(str_or_int):
        if not isinstance(str_or_int, float):
            str_or_int = Timestamps.str2unix(str_or_int)
        return datetime.datetime.utcfromtimestamp(str_or_int).strftime('%Y-%m-%d_%H:%M:%S')


class Journals:
    @staticmethod
    def read_logs(*args):
        journal_args = [
                'journalctl',
                '-o', 'json',
                '-u', 'kres*',
                '-u', 'systemd-coredump*']
        journal_args += args
        with subprocess.Popen(journal_args,
                bufsize=1,  # line buffering
                universal_newlines=True,
                stdout=subprocess.PIPE) as jproc:
            for line in jproc.stdout:
                yield json.loads(line)

    @staticmethod
    def extract_logs(around_time, log_name):
        start_time = around_time - TIMESPAN_BEFORE
        end_time = around_time + TIMESPAN_AFTER
        log_window = list(Journals.read_logs(
                '--since=@{}'.format(start_time),
                '--until=@{}'.format(end_time)
            ))
        with log_name.with_suffix('.json').open('w') as jsonf:
            json.dump(log_window, jsonf, indent=4)
        with log_name.with_suffix('.log').open('w') as logf:
            logf.write('##### logs since {}\n'.format(Timestamps.unix2print(start_time)))
            for entry in log_window:
                entry_time = Timestamps.str2unix(entry['__REALTIME_TIMESTAMP'])
                if entry_time == around_time:
                    logf.write('##### HERE #####\n')
                logf.write('{t} {h} {prg}[{pid}]: {m}\n'.format(
                    t=Timestamps.unix2print(entry_time),
                    h=entry['_HOSTNAME'],
                    prg=(
                            entry.get('COREDUMP_UNIT')
                            or entry.get('UNIT')
                            or entry.get('_SYSTEMD_UNIT')
                            or entry['SYSLOG_IDENTIFIER']
                        ),
                    pid=entry.get('COREDUMP_PID') or entry['_PID'],
                    m=entry['MESSAGE']
                    )
                )
            logf.write('##### logs until {}\n'.format(Timestamps.unix2print(end_time)))


def main():
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) != 2:
        sys.exit('Usage: %s <output log directory>'.format(sys.argv[0]))
    outdir = pathlib.Path(sys.argv[1])
    outdir.mkdir(parents=True, exist_ok=True)

    cursor_previous = Cursors.get_previous()
    cursor_at_start = Cursors.get_current()

    exit_times = []
    coredumps = {}
    filter_args = []
    if cursor_previous:
        filter_args = ['--after-cursor', cursor_previous]
    for entry in Journals.read_logs(*filter_args):
        if 'EXIT_CODE' in entry:
            exit_time = Timestamps.str2unix(entry['__REALTIME_TIMESTAMP'])
            logging.debug('exit@%s: %s', exit_time, entry)
            exit_times.append(exit_time)
        if 'COREDUMP_FILENAME' in entry:
            core_path = pathlib.Path(entry['COREDUMP_FILENAME'])
            core_time = Timestamps.str2unix(entry['__REALTIME_TIMESTAMP'])
            logging.debug('coredump @ %s: %s', core_time, core_path)
            coredumps[core_path] = core_time

    exit_times.sort()
    logging.debug('detected exits: %s', exit_times)
    for exit_time in exit_times:
        Journals.extract_logs(exit_time, outdir / '{}'.format(Timestamps.unix2print(exit_time)))

    coredumps_missing = 0
    logging.debug('detected coredumps: %s', coredumps)
    for core_path, core_time in coredumps.items():
        core_name = core_path.name
        timestamp = Timestamps.unix2print(core_time)
        out_path_prefix = (outdir / timestamp)
        Journals.extract_logs(core_time, out_path_prefix.with_suffix('.logs'))
        try:
            shutil.copy(
                str(core_path),
                str(out_path_prefix.with_suffix('.{}'.format(str(core_name)))))
        except FileNotFoundError as ex:
            logging.error('coredump file %s cannot be copied: %s', core_path, ex)
            coredumps_missing += 1
    logging.info('wrote %d coredumps and %d logs snippets (%s coredumps missing)',
                 len(coredumps) - coredumps_missing, len(exit_times), coredumps_missing)

    Cursors.overwrite_previous(cursor_at_start)

if __name__ == '__main__':
    main()
