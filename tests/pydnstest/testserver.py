import threading
import select, socket, struct, sys, os, time
import dns.message
import test
import binascii

# Test debugging
TEST_DEBUG = 0
if 'TEST_DEBUG' in os.environ:
    TEST_DEBUG = int(os.environ['TEST_DEBUG'])

g_lock = threading.Lock()
def syn_message(*args):
        g_lock.acquire()
        print args
        g_lock.release()

def recvfrom_message(stream):
    """ Receive DNS/UDP message. """
    if TEST_DEBUG > 0:
        syn_message("incoming data")
    data, addr = stream.recvfrom(8000)
    if TEST_DEBUG > 0:
        syn_message("[Python] received", len(data), "bytes from", addr)
    return dns.message.from_wire(data), addr

def sendto_message(stream, message, addr):
    """ Send DNS/UDP message. """
    if TEST_DEBUG > 0:
        syn_message("outgoing data")
    stream.sendto(message, addr)
    if TEST_DEBUG > 0:
        syn_message("[Python] sent", len(message), "bytes to", addr)

class SInfo:
    def __init__(self,type,addr,port,client_addr):
        self.type = type
        self.addr = addr
        self.port = port
        self.client_addr = client_addr
        self.thread = None
        self.active = False
        self.name = ''

class TestServer:
    """ This simulates UDP DNS server returning scripted or mirror DNS responses. """

    def __init__(self, scenario):
        """ Initialize server instance. """
        if TEST_DEBUG > 0:
            print "Test Server initialization"
        self.srv_socks = []
        self.client_socks = []
	self.active = False
        self.scenario = scenario

    def __del__(self):
        """ Cleanup after deletion. """
        if TEST_DEBUG > 0:
            print "Test Server cleanup"
        if self.active is True:
            self.stop()

    def start(self):
        """ Asynchronous start, returns immediately. """
        if TEST_DEBUG > 0:
            print "Test Server start"
        if self.active is True:
            raise Exception('server already started')
        self.active = True
        self.get_server_socket(None, socket.AF_INET)
        self.get_server_socket(None, socket.AF_INET6)

    def stop(self):
        """ Stop socket server operation. """
        if TEST_DEBUG > 0:
            syn_message("Test Server stop")
        self.active = False
        for srv_sock in self.srv_socks:
            if TEST_DEBUG > 0:
                syn_message("closing socket", srv_sock.name)
            srv_sock.active = False
            srv_sock.thread.join()
        for client_sock in self.client_socks:
            if TEST_DEBUG > 0:
                syn_message("closing client socket")
            client_sock.close()
        self.client_socks = []
        self.srv_socks = []
        self.scenario = None
        if TEST_DEBUG > 0:
            syn_message("server stopped")

    def address(self):
        addrlist = [];
        for s in self.srv_socks:
            addrlist.append(s.name);
        return addrlist;

    def handle_query(self, client, client_address):
        """ Handle incoming queries. """
        query, addr = recvfrom_message(client)
        if TEST_DEBUG > 0:
            syn_message("incoming query from", addr, "client", client_address)
        if TEST_DEBUG > 1:
            syn_message("=========\n",query,"=========")
        if query is None:
            if TEST_DEBUG > 0:
                syn_message("Empty query")
            return False
        response = dns.message.make_response(query)
        is_raw_data = False
        if self.scenario is not None:
            if TEST_DEBUG > 0:
                syn_message("get scenario reply")
            response, is_raw_data = self.scenario.reply(query, client_address)
        if response:
            if TEST_DEBUG > 0:
                syn_message("sending answer")
            if TEST_DEBUG > 1:
                syn_message("=========\n",response,"=========")
            if is_raw_data is False:
                sendto_message(client, response.to_wire(), addr)
            else:
                sendto_message(client, response, addr)
            return True
        else:
            if TEST_DEBUG > 0:
                syn_message("response is NULL")
            return False

    def query_io(self,srv_sock):
        """ Main server process """
        if TEST_DEBUG > 0:
            syn_message("query_io starts")
        if self.active is False:
            raise Exception('Test server not active')
        res = socket.getaddrinfo(srv_sock.addr,srv_sock.port,srv_sock.type,0,socket.IPPROTO_UDP)
        serv_sock = socket.socket(srv_sock.type, socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        entry0 = res[0]
        sockaddr = entry0[4]
        serv_sock.bind(sockaddr)
        serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        address = serv_sock.getsockname()
        srv_sock.name = address
        clients = [serv_sock]
        srv_sock.active = True
        if TEST_DEBUG > 0:
            syn_message("UDP query handler type", srv_sock.type, "started at", address)
        while srv_sock.active is True:
           to_read, _, to_error = select.select(clients, [], clients, 0.1)
           for sock in to_read:
              self.handle_query(sock,srv_sock.client_addr)
           for sock in to_error:
              raise Exception('Socket IO error, exit')
        serv_sock.close()
        if TEST_DEBUG > 0:
            syn_message("UDP query handler exit")


    def get_server_socket(self, client_addr, type = socket.AF_INET, address = None, port = 0):
        if TEST_DEBUG > 0:
            syn_message("getting server socket type",type,client_addr)
        if client_addr is not None:
            client_addr = client_addr.split('@')[0]
        if type == socket.AF_INET:
            if address is None:
                address = '127.0.0.1'
        elif type == socket.AF_INET6:
            if socket.has_ipv6 is not True:
                raise Exception('IPV6  is no supported')
            if address is None:
                address = "::1"
        else:
            print "unsupported socket type", self.sock_type
            raise Exception('unsupported socket type')
        for srv_sock in self.srv_socks:
            if srv_sock.type == type:
                srv_sock.client_addr = client_addr
                return srv_sock.name
        srv_sock = SInfo(type,address,port,client_addr)
        srv_sock.thread = threading.Thread(target=self.query_io, args=(srv_sock,))
        srv_sock.thread.start()
        while srv_sock.active is False:
            continue
        self.srv_socks.append(srv_sock)
        if TEST_DEBUG > 0:
            syn_message("socket started")
        return srv_sock.name

    def client(self, dst_addr = None):
        """ Return connected client. """
        if dst_addr is not None:
            dst_addr = dst_addr.split('@')[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockname = self.get_server_socket(dst_addr,socket.AF_INET)
        sock.connect(sockname)
        self.client_socks.append(sock)
        return sock, sockname

def test_sendrecv():
    """ Module self-test code. """
    server = TestServer(None)
    server.start()
    client, peer = server.client()
    try:
        query = dns.message.make_query('.', dns.rdatatype.NS)
        client.send(query.to_wire())
        answer, _ = recvfrom_message(client)
        if answer is None:
            raise Exception('no answer received')
        if not query.is_response(answer):
            raise Exception('not a mirror response')
    finally:
        server.stop()
        client.close()

if __name__ == '__main__':

    # Self-test code
    test = test.Test()
    test.add('testserver/sendrecv', test_sendrecv)
    if test.run() != 0:
        sys.exit(1)

    # Mirror server
    server = TestServer(None)
    server.start()
    server.get_server_socket(None, socket.AF_INET)
    print('[==========] Mirror server running at', server.address())
    try:
        while True:
	    time.sleep(0.5)
    except KeyboardInterrupt:
        print('[==========] Shutdown.')
        pass
    server.stop()
