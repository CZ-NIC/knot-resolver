class Query:

    match_fields = []

    def __init__(self):
        pass

    def match(self, fields):
        self.match_fields = fields

    def parse(self, text):
        pass

class Range:

    a = 0
    b = 0
    queries = []

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def add_query(self, query):
        self.queries.append(query)


class Scenario:

    name = ''
    ranges = []
    steps = []

    def __init__(self):
        pass

    def begin(self, explanation):
        print '# %s' % explanation

    def range(self, a, b):
        range_new = Range(a, b)
        self.ranges.append(range_new)
        return range_new

    def step(self, n, step_type):
        pass
