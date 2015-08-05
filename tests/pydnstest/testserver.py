import threading
import select, socket, struct, sys, os, time
import dns.message
import dns.rdatatype
import test
import binascii
import re
import itertools
import inspect

# Test debugging
TEST_DEBUG = 0
if 'TEST_DEBUG' in os.environ:
    TEST_DEBUG = int(os.environ['TEST_DEBUG'])

g_lock = threading.Lock()
def syn_print(tag, *args):
    """ Print message with some debug information included. """
    g_lock.acquire()
    if tag is None:
        tag = inspect.stack()[1][3]
    for s in args:
        print "[{:<12}][{}] {}".format(tag,threading.current_thread().name,s)
    g_lock.release()

def recvfrom_msg(stream):
    """ Receive DNS/UDP message. """
    if TEST_DEBUG > 0:
        syn_print(None, "incoming data")
    data, addr = stream.recvfrom(8000)
    if TEST_DEBUG > 0:
        syn_print(None, "received {len} butes from {addr}".format(len=len(data),addr=addr))
    return dns.message.from_wire(data), addr

def sendto_msg(stream, message, addr):
    """ Send DNS/UDP message. """
    if TEST_DEBUG > 0:
        syn_print(None, "outgoing data")
    stream.sendto(message, addr)
    if TEST_DEBUG > 0:
        syn_print(None,"{len} bytes sent to {addr}".format(len=len(message),addr=addr))

def get_local_addr_str(family, iface):
    """ Returns pattern string for localhost address  """
    if family == socket.AF_INET:
        addr_local_pattern = "127.0.0.{}"
    elif family == socket.AF_INET6:
        addr_local_pattern = "fd00::5357:5f{:02X}"
    else:
        raise Exception("[get_local_addr_str] family not supported '%i'" % family)
    return addr_local_pattern.format(iface)

class SrvSock (socket.socket):
    """ Socket with some additional info  """
    def __init__(self, client_address, family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP):
        self.client_address = client_address
        socket.socket.__init__(self, family, type, proto)

class AddrMapInfo:
    """ Saves mapping info between adresses from rpl and cwrap adresses """
    def __init__(self, family, local, external):
        self.family   = family
        self.local    = local
        self.external =  external

class TestServer:
    """ This simulates UDP DNS server returning scripted or mirror DNS responses. """

    def __init__(self, scenario, config, d_iface, p_iface):
        """ Initialize server instance. """
        if TEST_DEBUG > 0:
            syn_print(None, "initialization")
        self.thread = None
        self.srv_socks = []
        self.client_socks = []
        self.active = False
        self.scenario = scenario
        self.config = config
        self.addr_map = []
        self.start_iface = 2
        self.cur_iface = self.start_iface
        self.kroot_local = None
        self.kroot_family = None

        self.default_iface = d_iface
        self.peer_iface = p_iface

        self.map_adresses()
        self.start()


    def __del__(self):
        """ Cleanup after deletion. """
        if TEST_DEBUG > 0:
            syn_print(None, "cleanup")
        if self.active is True:
            self.stop()

    def start(self):
        """ Synchronous start """
        if TEST_DEBUG > 0:
            syn_print(None, "start")
        if self.active is True:
            if TEST_DEBUG > 0:
                syn_print(None, "TestServer already started")
        self.active = True
        self.start_srv(self.kroot_local, self.kroot_family)

    def stop(self):
        """ Stop socket server operation. """
        if TEST_DEBUG > 0:
            syn_print(None,"stop")
        self.active = False
        self.thread.join()
        for srv_sock in self.srv_socks:
            if TEST_DEBUG > 0:
                syn_print(None, "closing socket {name}".format(name=srv_sock.getsockname()))
            srv_sock.close()
        for client_sock in self.client_socks:
            if TEST_DEBUG > 0:
                syn_print(None, "closing client socket {name}".format(name=client_sock.getsockname()))
            client_sock.close()
        self.client_socks = []
        self.srv_socks = []
        self.scenario = None
        if TEST_DEBUG > 0:
            syn_print(None, "server stopped")

    def map_to_local(self, addr, family, iface):
        """ Maps arbitrary IP to localhost for using with cwrap """
        addr_external = None
        addr_local = None
        addr_local_pattern = None
        new_entry = None
        try:
            n = socket.inet_pton(family, addr)
            addr_external = socket.inet_ntop(family, n)
        except socket.error:
            return addr_local, new_entry
        for am in self.addr_map:
            if am.family == family and am.external == addr_external:
                 addr_local = am.local
                 new_entry = False
                  
        if addr_local is None:
            addr_local = get_local_addr_str(family, iface)
            am = AddrMapInfo(family,addr_local,addr_external)
            self.addr_map.append(am)
            new_entry = True
        return addr_local, new_entry        

    def get_local(self, addr, root):
        """ Maps arbitrary IP4 or IP6 addres to local address, """
        """ saves mapping info and returns local address to caller"""
        local_address = None
        iface = None
        is_new_entry = None
        family = None
        if root is True:
            iface = self.default_iface
        else:
            if self.cur_iface == self.default_iface or self.cur_iface == self.peer_iface:
                self.cur_iface = self.cur_iface + 1
            iface = self.cur_iface
        family = socket.AF_INET
        local_address, is_new_entry = self.map_to_local(addr, family, iface)
        if local_address is None:
            family = socket.AF_INET6
            local_address, is_new_entry = self.map_to_local(addr, family, iface);
            if local_address is None:
                family = None
        if root is False and is_new_entry is True:
            self.cur_iface = self.cur_iface + 1
            while self.cur_iface == self.default_iface or self.cur_iface == self.peer_iface:
                self.cur_iface = self.cur_iface + 1
        return local_address, family

    def get_external(self, local_address, family):
        """ Fetches external address mapped to local_address """
        external_address = None
        for am in self.addr_map:
            if am.local == local_address and am.family == family:
                external_address = am.external

        return external_address


    def map_entries(self, entrylist):
        """ Translate addresses for A and AAAA records"""
        for entry in entrylist :
            for rr in itertools.chain(entry.message.answer,entry.message.additional,entry.message.question,entry.message.authority):
                if TEST_DEBUG > 0:
                    syn_print(None,"rrset = {}".format(rr))
                for rd in rr:
                    if rd.rdtype == dns.rdatatype.A or rd.rdtype == dns.rdatatype.AAAA:
                         rd_local_address, family = self.get_local(rd.address,False)
                         if TEST_DEBUG > 0:
                             if rd_local_address is None:
                                 syn_print(None,"!!! rd address %s not translated" % (rd.to_text()))
                             else:
                                 syn_print(None,"rd address %s translated to %s" % (rd.to_text(),rd_local_address))
                         rd.address = rd_local_address

    def map_adresses(self):
        """ Translate addresses for whole scenario """
        """ Raw data not translated """
        if self.config is None:
            self.kroot_family = socket.AF_INET
            self.kroot_local = get_local_addr_str(self.kroot_family, self.default_iface)
            return
        if TEST_DEBUG > 0:
            syn_print(None,"translating config")
        kroot_addr = None
        for k, v in self.config:
            if k == 'stub-addr':
                kroot_addr = v
        if kroot_addr is not None:
            self.kroot_local, self.kroot_family = self.get_local(kroot_addr, True)
            if self.kroot_local is None:
                raise Exception("[map_adresses] Invalid K.ROOT-SERVERS.NET. address, check the config")

            if TEST_DEBUG > 0:
                syn_print(None,"K.ROOT-SERVERS.NET. %s translated to %s" % (kroot_addr, self.kroot_local))
        else:
            if TEST_DEBUG > 0:
                syn_print(None,"K.ROOT-SERVERS.NET. address not found")
        if TEST_DEBUG > 0:
            syn_print(None,"translating ranges")
        for rng in self.scenario.ranges :
            range_local_address, family = self.get_local(rng.address, False)
            if range_local_address is None:
                raise Exception("[map_adresses] Error translating address '%s', check the config" % rng.address)
            if TEST_DEBUG > 0:
                syn_print(None,"range addr '%s' translated to '%s'" % (rng.address, range_local_address))
            rng.address = range_local_address
            self.map_entries(rng.stored)
        if TEST_DEBUG > 0:
            syn_print(None,"translating steps")
        for stp in self.scenario.steps :
            self.map_entries(stp.data)
    
    def address(self):
        """ Returns opened sockets list """
        addrlist = [];
        for s in self.srv_socks:
            addrlist.append(s.getsockname());
        return addrlist;

    def handle_query(self, client):
        """ Handle incoming queries. """
        client_address = client.client_address
        query, addr = recvfrom_msg(client)
        if TEST_DEBUG > 0:
            syn_print(None, "incoming query from {}; client address {}, mapped to external {}".format(addr, client_address, self.get_external(client_address, client.family)))
        if TEST_DEBUG > 1:
            syn_print(None,"========= INCOMING QUERY START =========")
            syn_print(None,query)
            syn_print(None,"========= INCOMING QUERY END   =========")
        if query is None:
            if TEST_DEBUG > 0:
                syn_print(None,"Empty query")
            return False
        response = dns.message.make_response(query)
        is_raw_data = False
        if self.scenario is not None:
            if TEST_DEBUG > 0:
                syn_print(None,"get scenario reply")
            response, is_raw_data = self.scenario.reply(query, client_address)
        if response:
            if TEST_DEBUG > 0:
                syn_print(None,"sending answer")
            if TEST_DEBUG > 1:
                syn_print(None,"========= RESPONSE START =========")
                syn_print(None,response)
                syn_print(None,"========= RESPONSE END =========")


            if TEST_DEBUG > 1:
                syn_print(None, "parse response")
            if is_raw_data is False:
                for rr in itertools.chain(response.answer,response.additional,response.question,response.authority):
                    if TEST_DEBUG > 1:
                        syn_print(None,"rrset = {}".format(rr))
                    for rd in rr:
                        if rd.rdtype == dns.rdatatype.A:
                            if TEST_DEBUG > 1:
                                 syn_print(None,"rd address =", rd.address)
                            self.start_srv(rd.address, socket.AF_INET)
                        elif rd.rdtype == dns.rdatatype.AAAA:
                            if TEST_DEBUG > 1:
                                syn_print(None,"rd address =", rd.address)
                            self.start_srv(rd.address, socket.AF_INET6)
                sendto_msg(client, response.to_wire(), addr)
            else:
                sendto_msg(client, response, addr)

            return True
        else:
            if TEST_DEBUG > 0:
                syn_print(None,"response is NULL, sending RECVFAIL")
            response = dns.message.make_response(query)
            response.rcode = dns.rcode.SERVFAIL
            sendto_msg(client, response.to_wire(), addr)
            return False

    def query_io(self):
        """ Main server process """
        if self.active is False:
            raise Exception("[query_io] Test server not active")
        if TEST_DEBUG > 0:
            syn_print(None,"UDP query io handler started")

        while self.active is True:
           to_read, _, to_error = select.select(self.srv_socks, [], self.srv_socks, 0.1)
           for sock in to_read:
              self.handle_query(sock)
           for sock in to_error:
              if TEST_DEBUG > 0:
                  syn_print(None,"Error for socket {}".format(sock.getsockname()))
              raise Exception("[query_io] Socket IO error {}, exit".format(sock.getsockname()))
        if TEST_DEBUG > 0:
            syn_print(None,"UDP query io handler exit")


    def start_srv(self, address = None, family = socket.AF_INET, port = 53):
        """ Starts listening thread if necessary """
        if TEST_DEBUG > 0:
            syn_print(None,"starting socket; type {} {} {}".format(family,address,port))
        if family == None:
            family = socket.AF_INET
        if family == socket.AF_INET:
            if address == '' or address is None:
                address = "127.0.0.{}".format(self.default_iface)
        elif family == socket.AF_INET6:
            if socket.has_ipv6 is not True:
                raise Exception("[start_srv] IPV6 is not supported")
            if address == '' or address is None:
                address = "::1"
        else:
            syn_print(None, "unsupported socket type {sock_type}".format(sock_type=type))
            raise Exception("[start_srv] unsupported socket type {sock_type}".format(sock_type=type))
	if port == 0 or port is None:
            port = 53

        if (self.thread is None):
            self.thread = threading.Thread(target=self.query_io)
            self.thread.start()

        for srv_sock in self.srv_socks:
            if srv_sock.family == family and srv_sock.client_address == address :
                if TEST_DEBUG > 0:
                    syn_print(None, "server socket {} already started".format(srv_sock.getsockname()) )
                return srv_sock.getsockname()
    
        addr_info = socket.getaddrinfo(address,port,family,0,socket.IPPROTO_UDP)
        sock = SrvSock(address, family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        addr_info_entry0 = addr_info[0]
        sockaddr = addr_info_entry0[4]
        sock.bind(sockaddr)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_socks.append(sock)
        sockname = sock.getsockname()
        if TEST_DEBUG > 0:
            syn_print(None, "server socket {} started".format(sockname))
        return sockname

    def client(self, dst_addr = None):
        """ Return connected client. """
        if dst_addr is not None:
            dst_addr = dst_addr.split('@')[0]
        sockname = self.start_srv(dst_addr, socket.AF_INET)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(sockname)
        self.client_socks.append(sock)
        return sock, sockname

    def play(self):
        saddr = get_local_addr_str(socket.AF_INET,self.default_iface)
        paddr = get_local_addr_str(socket.AF_INET,self.peer_iface)
        self.scenario.play(saddr,paddr)


def test_sendrecv(default_iface,peer_iface):
    """ Module self-test code. """
    server = TestServer(None,None,default_iface,peer_iface)
    server.start()
    client, peer = server.client()
    try:
        query = dns.message.make_query('.', dns.rdatatype.NS)
        client.send(query.to_wire())
        answer, _ = recvfrom_msg(client)
        if answer is None:
            raise Exception("[test_sendrecv] no answer received")
        if not query.is_response(answer):
            raise Exception("[test_sendrecv] not a mirror response")
    finally:
        server.stop()
        client.close()

if __name__ == '__main__':

    # Self-test code
    DEFAULT_IFACE = 0
    CHILD_IFACE = 0
    if "SOCKET_WRAPPER_DEFAULT_IFACE" in os.environ:
       DEFAULT_IFACE = int(os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"])
    if DEFAULT_IFACE < 2 or DEFAULT_IFACE > 254 :
        if TEST_DEBUG > 0:
            syn_print(None,"SOCKET_WRAPPER_DEFAULT_IFACE is invalid ({}), set to default (10)".format(DEFAULT_IFACE))
        DEFAULT_IFACE = 10
        os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"]="{}".format(DEFAULT_IFACE)

    test = test.Test()
    test.add('testserver/sendrecv', test_sendrecv, DEFAULT_IFACE, DEFAULT_IFACE)
    if test.run() != 0:
        sys.exit(1)

    # Mirror server
    server = TestServer(None,None,DEFAULT_IFACE,DEFAULT_IFACE)
    server.start()
    syn_print("main","[==========] Mirror server running at", server.address())
    try:
        while True:
	    time.sleep(0.5)
    except KeyboardInterrupt:
        syn_print("main","[==========] Shutdown.")
        pass
    server.stop()
