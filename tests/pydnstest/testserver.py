import SocketServer, socket, threading, struct
import dns.message


class DNSHandler(SocketServer.BaseRequestHandler):
    """ This handler returns prescripted or mirror DNS responses. """

    def handle(self):
        """ Handle incoming queries. """
        wire_len = self.request.recv(2)
        if len(wire_len) != 2:
            return
        wire_len = struct.unpack("!H", wire_len)[0]
        query = dns.message.from_wire(self.request.recv(wire_len))

        # Echo service if no scenario
        response = dns.message.make_response(query)
        if self.server.scenario is not None:
            response = self.server.scenario.reply(query)
        if response:
            response = response.to_wire()
            self.request.send(struct.pack('!H', len(response)) + response)


class TestServer:
    """ This simulates TCP DNS server returning prescripted or mirror DNS responses. """

    def __init__(self, scenario, host='127.0.0.1', port=0):
        self.server = SocketServer.TCPServer((host, port), DNSHandler)
        self.server.allow_reuse_address = True
        self.server.scenario = scenario

    def start(self):
        """ Asynchronous start, returns immediately. """
        self.thread = threading.Thread(target=self.run)
        self.thread.start()

    def run(self):
        """ Synchronous start, waits until server closes or for an interrupt. """
        self.server.serve_forever()

    def stop(self):
        """ Stop socket server operation. """
        self.server.shutdown()

    def client(self):
        """ Return connected client. """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(self.server.server_address)
        return sock


if __name__ == '__main__':

    server = TestServer(None)
    print('mirror server running at %s' % str(server.server.server_address))
    try:
        server.run()
    except KeyboardInterrupt:
        pass
    server.stop()