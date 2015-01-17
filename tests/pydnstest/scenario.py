import traceback
import dns.message
import dns.rrset
import dns.rcode


class Entry:
    default_ttl = 3600
    default_cls = 'IN'
    default_rc = 'NOERROR'

    def __init__(self):
        self.match_fields = None
        self.adjust_fields = None
        self.message = dns.message.Message()

    def match_part(self, code, msg):
        if code not in self.match_fields and 'all' not in self.match_fields:
            return True
        expected = self.message
        if code == 'opcode':
            return self.__compare_val(expected.opcode(), msg.opcode())
        elif code == 'qtype':
            return self.__compare_val(expected.question[0].rdtype, msg.question[0].rdtype)
        elif code == 'qname':
            return self.__compare_val(expected.question[0].name, msg.question[0].name)
        elif code == 'flags':
            return self.__compare_val(dns.flags.to_text(expected.flags), dns.flags.to_text(msg.flags))
        elif code == 'question':
            return self.__compare_rrs(expected.question, msg.question)
        elif code == 'answer':
            return self.__compare_rrs(expected.answer, msg.answer)
        elif code == 'authority':
            return self.__compare_rrs(expected.authority, msg.authority)
        elif code == 'additional':
            return self.__compare_rrs(expected.additional, msg.additional)
        else:
            raise Exception('unknown match request "%s"' % code)

    def match(self, msg):
        match_fields = self.match_fields
        if 'all' in match_fields:
            match_fields = ('flags', 'question', 'answer', 'authority', 'additional')
        for code in match_fields:
            try:
                self.match_part(code, msg)
            except Exception as e:
                raise Exception("when matching %s: %s" % (code, str(e)))

    def set_match(self, fields):
        self.match_fields = fields

    def set_adjust(self, fields):
        self.adjust_fields = fields

    def set_reply(self, fields):
        flags = []
        rcode = dns.rcode.from_text(self.default_rc)
        for code in fields:
            try:
                rcode = dns.rcode.from_text(code)
            except:
                flags.append(code)
        self.message.flags = dns.flags.from_text(' '.join(flags))
        self.message.rcode = rcode

    def begin_section(self, section):
        self.section = section

    def add_record(self, owner, args):
        rr = self.__rr_from_str(owner, args)
        if self.section == 'QUESTION':
            self.message.question.append(rr)
        elif self.section == 'ANSWER':
            self.message.answer.append(rr)
        elif self.section == 'AUTHORITY':
            self.message.authority.append(rr)
        elif self.section == 'ADDITIONAL':
            self.message.additional.append(rr)
        else:
            raise Exception('attempted to add record in section %s' % self.section)


    def __rr_from_str(self, owner, args):
        ttl = self.default_ttl
        rdclass = self.default_cls
        try:
            dns.ttl.from_text(args[0])
            ttl = args.pop(0)
        except:
            pass  # optional
        try:
            dns.rdataclass.from_text(args[0])
            rdclass = args.pop(0)
        except:
            pass  # optional
        rdtype = args.pop(0)
        if len(args) > 0:
            return dns.rrset.from_text(owner, ttl, rdclass, rdtype, ' '.join(args))
        else:
            return dns.rrset.from_text(owner, ttl, rdclass, rdtype)

    def __compare_rrs(self, name, expected, got):
        for rr in expected:
            if rr not in got:
                raise Exception("expected record '%s'" % rr.to_text())
        for rr in got:
            if rr not in expected:
                raise Exception("unexpected record '%s'" % rr.to_text())
        return True

    def __compare_val(self, expected, got):
        if expected != got:
            raise Exception("expected '%s', got '%s'" % (expected, got))
        return True


class Range:
    def __init__(self, a, b):
        self.a = a
        self.b = b
        self.queries = []

    def add(self, entry):
        self.queries.append(entry)


class Step:
    def __init__(self, id, type):
        self.id = int(id)
        self.type = type
        self.data = []

    def add(self, entry):
        self.data.append(entry)

    def play(self, ctx):
        if self.type == 'QUERY':
            return self.__query(ctx)
        elif self.type == 'CHECK_ANSWER':
            return self.__check_answer(ctx)
        else:
            print '%d %s (%d entries) => NOOP' % (self.id, self.type, len(self.data))
            return None

    def __check_answer(self, ctx):
        if len(self.data) == 0:
            raise Exception("response definition required")
        if ctx.last_answer is None:
            raise Exception("no answer from preceding query")
        expected = self.data[0]
        expected.match(ctx.last_answer)

    def __query(self, ctx):
        if len(self.data) == 0:
            raise Exception("query definition required")
        msg = self.data[0].message
        self.answer = ctx.resolve(msg.to_wire())
        if self.answer is not None:
            self.answer = dns.message.from_wire(self.answer)
            ctx.last_answer = self.answer


class Scenario:
    def __init__(self, info):
        print '# %s' % info
        self.ranges = []
        self.steps = []

    def play(self, ctx):
        step = None
        if len(self.steps) == 0:
            raise ('no steps in this scenario')
        try:
            for step in self.steps:
                step.play(ctx)
        except Exception as e:
            raise Exception('on step #%d "%s": %s\n%s' % (step.id, step.type, str(e), traceback.format_exc()))


