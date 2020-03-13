from cmd import Cmd

prog_name = "kresctl"
prog_version = ""
prog_desc = f"{prog_name} (Knot Resolver) control/configuration tool"

class Interactive(Cmd):

    def __init__(self, prompt_str=prog_name):
        super().__init__()
        self.prompt = f'{prompt_str}> '


    def do_exit(self, inp):
        return True

    def help_exit(self):
        print('exit the application. Shorthand: x q Ctrl-D.')

    def do_add(self, inp):
        print("adding '{}'".format(inp))

    def help_add(self):
        print("Add a new entry to the system.")

    def default(self, inp):
        if inp == 'x' or inp == 'q':
            return self.do_exit(inp)

        print("Default: {}".format(inp))

    do_EOF = do_exit
    help_EOF = help_exit
