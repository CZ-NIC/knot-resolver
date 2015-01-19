#!/usr/bin/python -Es
# vim: et:sw=4:ts=4:sts=4
#
# Script regenerates project file list from the list of files tracked by Git.
#

SOURCES = [
    # documentation
    "README", "KNOWN_ISSUES", 
    "Doxyfile*", "Doxy.file.h", "doc/*.rst",

    # build-system
    "*.ac", "*.am",

    # sources
    "lib/*.c", "lib/*.h", "lib/layer/*.h", "lib/layer/*.c",
    "tests/*.c", "tests/*.h", "tests/*.py",
    "daemon/*.c", "daemon/*.h", "daemon/layer/*.c", "daemon/layer/*.h"
]

OUTPUT_FILE = "knot-resolver.files"

# ----------------------------------------------------------------------------

from subprocess import Popen, PIPE
import os
import sys

def run(command):
    p = Popen(command, stdout=PIPE, stderr=PIPE)
    (out, errout) = p.communicate()
    if p.returncode != 0:
        raise Exception("Command %s failed.", command)
    return out

print >>sys.stderr, "Updating %s." % OUTPUT_FILE

git_root = run(["git", "rev-parse", "--show-toplevel"]).strip()
os.chdir(git_root)

command = ["git", "ls-files"] + SOURCES
files = run(command).splitlines()

with open(OUTPUT_FILE, "w") as output:
    output.write("\n".join(sorted(files)))
    output.write("\n")
