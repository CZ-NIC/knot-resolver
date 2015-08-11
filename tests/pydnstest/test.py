#!/usr/bin/env python

class Test:
    """ Small library to imitate CMocka output. """

    def __init__(self):
        self.tests = []

    def add(self, name, test, *args):
        """ Add named test to set. """
        self.tests.append((name, test, args))

    def run(self):
        """ Run planned tests. """
        planned = len(self.tests)
        passed = 0
        if planned == 0:
            return

        print('[==========] Running %d test(s).' % planned)
        for name, test_callback, args in self.tests:
            print('[ RUN      ] %s' % name)
            try:
                test_callback(*args)
                passed += 1
                print('[       OK ] %s' % name)
            except Exception as e:
                print('[     FAIL ] %s (%s)' % (name, str(e)))

        # Clear test set
        self.tests = []
        print('[==========] %d test(s) run.' % planned)
        if passed == planned:
            print('[  PASSED  ] %d test(s).' % passed)
            return 0
        else:
            print('[  FAILED  ] %d test(s).' % (planned - passed))
            return 1
