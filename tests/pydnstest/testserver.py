import select, socket, threading, struct, sys, os
import dns.message
import test

def recv_message(stream):
    """ Receive DNS/TCP message. """
    wire_len = stream.recv(2)
    if len(wire_len) != 2:
       return None
    wire_len = struct.unpack("!H", wire_len)[0]
    return dns.message.from_wire(stream.recv(wire_len))

def send_message(stream, message):
    """ Send DNS/TCP message. """
    message = message.to_wire()
    stream.send(struct.pack('!H', len(message)) + message)

class TestServer:
    """ This simulates TCP DNS server returning prescripted or mirror DNS responses. """

    def __init__(self, scenario, type = socket.AF_UNIX, address = '.test_server.sock', port = 0):
        """ Initialize server instance. """
        self.is_active = False
        self.thread = None
        self.sock = socket.socket(type, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if type == socket.AF_UNIX:
            if os.path.exists(address):
                os.unlink(address)
            self.sock.bind(address)
        else:
            self.sock.bind((address, port))
        self.sock.listen(5)
        self.sock_type = type
        self.scenario = scenario

    def __del__(self):
        """ Cleanup after deletion. """
        if self.is_active:
            self.stop()

    def handle(self, client):
        """ Handle incoming queries. """
        query = recv_message(client)
        if query is None:
            return False
        response = dns.message.make_response(query)
        if self.scenario is not None:
            response = self.scenario.reply(query)
        if response:
            send_message(client, response)
            return True
        else:
            return False

    def start(self):
        """ Asynchronous start, returns immediately. """
        if self.is_active is True:
            raise Exception('server already started')
        self.is_active = True
        self.thread = threading.Thread(target = self.run)
        self.thread.start()

    def run(self):
        """ Synchronous start, waits until server closes or for an interrupt. """
        self.is_active = True
        clients = [self.sock]
        while self.is_active and len(clients):
            to_read, _, to_error = select.select(clients, [], clients, 0.5)
            for sock in to_read:
                if sock == self.sock:
                    clients.append(sock.accept()[0])
                else:
                    if not self.handle(sock):
                        to_error.append(sock)
            for sock in to_error:
                clients.remove(sock)
                sock.close()

    def stop(self):
        """ Stop socket server operation. """
        self.is_active = False
        if self.thread is not None:
            self.thread.join()
            self.thread = None
        if self.sock_type == socket.AF_UNIX:
            address = self.sock.getsockname()
            if os.path.exists(address):
                os.remove(address)

    def client(self):
        """ Return connected client. """
        sock = socket.socket(self.sock_type, socket.SOCK_STREAM)
        sock.connect(self.sock.getsockname())
        return sock

    def address(self):
        """ Return bound address. """
        address = self.sock.getsockname()
        if self.sock_type == socket.AF_UNIX:
            address = (address, 0)
        return address

def test_sendrecv():
    """ Module self-test code. """
    server = TestServer(None)
    client = server.client()
    server.start()
    try:
        query = dns.message.make_query('.', dns.rdatatype.NS)
        send_message(client, query)
        answer = recv_message(client)
        if answer is None:
            raise Exception('no answer received')
        if not query.is_response(answer):
            raise Exception('not a mirror response')
    finally:
        client.close()
        server.stop()

if __name__ == '__main__':

    # Self-test code
    if '--test' in sys.argv:
        test = test.Test()
        test.add('testserver/sendrecv', test_sendrecv)
        sys.exit(test.run())

    # Mirror server
    server = TestServer(None, socket.AF_INET, '127.0.0.1')
    print('mirror server running at %s' % str(server.address()))
    try:
        server.run()
    except KeyboardInterrupt:
         pass
    server.stop()
