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


class SInfo:
    def __init__(self,type,addr,port,client_addr):
        self.type = type
        self.addr = addr
        self.port = port
        self.client_addr = client_addr
        self.thread = None
        self.active = False
        self.name = ''

class AddrMapInfo:
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


    def __del__(self):
        """ Cleanup after deletion. """
        if TEST_DEBUG > 0:
            syn_print(None, "cleanup")
        if self.active is True:
            self.stop()

    def start(self):
        """ Asynchronous start, returns immediately. """
        if TEST_DEBUG > 0:
            syn_print(None, "start")
        if self.active is True:
            raise Exception('TestServer already started')
        self.active = True
        self.start_srv(self.kroot_local, self.kroot_family, self.kroot_local)

    def stop(self):
        """ Stop socket server operation. """
        if TEST_DEBUG > 0:
            syn_print(None,"stop")
        self.active = False
        for srv_sock in self.srv_socks:
            if TEST_DEBUG > 0:
                syn_print(None, "closing socket {name}".format(name=srv_sock.name))
            srv_sock.active = False
            srv_sock.thread.join()
        for client_sock in self.client_socks:
            if TEST_DEBUG > 0:
                syn_print(None, "closing client socket")
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
        m = re.search("(?P<kroot>\S+)\s+#\s+K.ROOT-SERVERS.NET.", self.config)
        if m is not None:
#            raise Exception("[map_adresses] Can't parse K.ROOT-SERVERS.NET. address, check the config")
            kroot_addr = m.group("kroot")
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
            addrlist.append(s.name);
        return addrlist;

    def handle_query(self, client, client_address):
        """ Handle incoming queries. """
        query, addr = recvfrom_msg(client)
        if TEST_DEBUG > 0:
            syn_print(None, "incoming query from {addr}; client={client}".format(addr=addr, client=client_address))
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
                            self.start_srv(rd.address, socket.AF_INET, rd.address)
                        elif rd.rdtype == dns.rdatatype.AAAA:
                            if TEST_DEBUG > 1:
                                syn_print(None,"rd address =", rd.address)
                            self.start_srv(rd.address, socket.AF_INET6, rd.address)
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

    def query_io(self,srv_sock):
        """ Main server process """
        if TEST_DEBUG > 0:
            syn_print(None,"query_io starts")
        if self.active is False:
            raise Exception("[query_io] Test server not active")
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
            syn_print(None,"UDP query handler type {type} started at {addr}".format(type=srv_sock.type,addr=address))
        while srv_sock.active is True:
           to_read, _, to_error = select.select(clients, [], clients, 0.1)
           for sock in to_read:
              self.handle_query(sock,srv_sock.client_addr)
           for sock in to_error:
              if TEST_DEBUG > 0:
                  syn_print(None,"Socket error")
              raise Exception("[query_io] Socket IO error, exit")
        serv_sock.close()
        if TEST_DEBUG > 0:
            syn_print(None,"UDP query handler exit")


    def start_srv(self, client_addr, type = socket.AF_INET, address = None, port = 53):
        """ Starts listening thread if necessary """
        if TEST_DEBUG > 0:
            syn_print(None,"starting server thread; socket type {type} {address} client {client_addr}".format(type=type,address=address,client_addr=client_addr))
        if type == None:
            type = socket.AF_INET
        if type == socket.AF_INET:
            if address == '' or address is None:
                address = "127.0.0.{}".format(self.default_iface)
        elif type == socket.AF_INET6:
            if socket.has_ipv6 is not True:
                raise Exception("[start_srv] IPV6 is not supported")
            if address == '' or address is None:
                address = "::1"
        else:
            syn_print(None, "unsupported socket type {sock_type}".format(sock_type=type))
            raise Exception("[start_srv] unsupported socket type {sock_type}".format(sock_type=type))
        if client_addr is not None:
            client_addr = client_addr.split('@')[0]
        else:
            client_addr = address
	if port == 0 or port is None:
            port = 53
        for srv_sock in self.srv_socks:
            if srv_sock.type == type and srv_sock.client_addr == client_addr :
                if TEST_DEBUG > 0:
                    syn_print(None, "server thread '%s' at '%s' already started" % (srv_sock.thread.name, srv_sock.addr) )
                return srv_sock.name
        srv_sock = SInfo(type,address,port,client_addr)
        srv_sock.thread = threading.Thread(target=self.query_io, args=(srv_sock,))
        srv_sock.thread.start()
        while srv_sock.active is False:
            continue
        self.srv_socks.append(srv_sock)
        if TEST_DEBUG > 0:
            syn_print(None, "server thread '%s' at '%s:%i' started" % (srv_sock.thread.name, srv_sock.addr, srv_sock.port))
        return srv_sock.name

    def client(self, dst_addr = None):
        """ Return connected client. """
        if dst_addr is not None:
            dst_addr = dst_addr.split('@')[0]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sockname = self.start_srv(dst_addr,socket.AF_INET)
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
    test = test.Test()
    test.add('testserver/sendrecv', test_sendrecv)
    if test.run() != 0:
        sys.exit(1)

    # Mirror server
    server = TestServer(None)
    server.start()
    server.start_srv(None, socket.AF_INET)
    syn_print("main","[==========] Mirror server running at", server.address())
    try:
        while True:
	    time.sleep(0.5)
    except KeyboardInterrupt:
        syn_print("main","[==========] Shutdown.")
        pass
    server.stop()
