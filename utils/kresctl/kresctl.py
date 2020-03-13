import os
import sys
import argparse

import yang
import sysrepo

from interactive import Interactive

def main():
    try:
        Interactive().cmdloop()
    except KeyboardInterrupt:
        print("")
        return

if __name__ == "__main__":
    sys.exit(main())
