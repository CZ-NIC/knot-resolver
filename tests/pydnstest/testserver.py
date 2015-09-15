import threading
import select
import socket
import os
import time
import dns.message
import dns.rdatatype
import itertools

def recvfrom_msg(stream):
    """ Receive DNS/UDP message. """
    data, addr = stream.recvfrom(4096)
    return dns.message.from_wire(data), addr

def sendto_msg(stream, message, addr):
    """ Send DNS/UDP message. """
    try:
        stream.sendto(message, addr)
    except: # Failure to respond is OK, resolver should recover
        pass

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

    def __del__(self):
        """ Cleanup after deletion. """
        if self.active is True:
            self.stop()

    def start(self):
        """ Synchronous start """
        if self.active is True:
            raise Exception('TestServer already started')
        self.active = True
        self.start_srv(self.kroot_local, self.kroot_family)

    def stop(self):
        """ Stop socket server operation. """
        self.active = False
        self.thread.join()
        for srv_sock in self.srv_socks:
            srv_sock.close()
        for client_sock in self.client_socks:
            client_sock.close()
        self.client_socks = []
        self.srv_socks = []
        self.scenario = None

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
            # Do not remap addresses already in local range
            if addr.startswith('127.0.0.') or addr.startswith('::'):
                addr_local = addr
            else:
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
                for rd in rr:
                    if rd.rdtype == dns.rdatatype.A or rd.rdtype == dns.rdatatype.AAAA:
                         rd_local_address, family = self.get_local(rd.address,False)
                         rd.address = rd_local_address

    def map_adresses(self):
        """ Translate addresses for whole scenario """
        """ Raw data not translated """
        if self.config is None:
            self.kroot_family = socket.AF_INET
            self.kroot_local = get_local_addr_str(self.kroot_family, self.default_iface)
            return
        kroot_addr = None
        for k, v in self.config:
            if k == 'stub-addr':
                kroot_addr = v
        if kroot_addr is not None:
            self.kroot_local, self.kroot_family = self.get_local(kroot_addr, True)
            if self.kroot_local is None:
                raise Exception("[map_adresses] Invalid K.ROOT-SERVERS.NET. address, check the config")
        for rng in self.scenario.ranges :
            range_local_address, family = self.get_local(rng.address, False)
            if range_local_address is None:
                raise Exception("[map_adresses] Error translating address '%s', check the config" % rng.address)
            rng.address = range_local_address
            self.map_entries(rng.stored)
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
        if query is None:
            return False
        response = dns.message.make_response(query)
        is_raw_data = False
        if self.scenario is not None:
            response, is_raw_data = self.scenario.reply(query, client_address)
        if response:
            if is_raw_data is False:
                for rr in itertools.chain(response.answer,response.additional,response.question,response.authority):
                    for rd in rr:
                        if rd.rdtype == dns.rdatatype.A:
                            self.start_srv(rd.address, socket.AF_INET)
                        elif rd.rdtype == dns.rdatatype.AAAA:
                            self.start_srv(rd.address, socket.AF_INET6)
                sendto_msg(client, response.to_wire(), addr)
            else:
                sendto_msg(client, response, addr)

            return True
        else:
            response = dns.message.make_response(query)
            response.rcode = dns.rcode.SERVFAIL
            sendto_msg(client, response.to_wire(), addr)
            return False

    def query_io(self):
        """ Main server process """
        if self.active is False:
            raise Exception("[query_io] Test server not active")
        while self.active is True:
           to_read, _, to_error = select.select(self.srv_socks, [], self.srv_socks, 0.1)
           for sock in to_read:
              self.handle_query(sock)
           for sock in to_error:
              raise Exception("[query_io] Socket IO error {}, exit".format(sock.getsockname()))

    def start_srv(self, address = None, family = socket.AF_INET, port = 53):
        """ Starts listening thread if necessary """
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
            raise Exception("[start_srv] unsupported socket type {sock_type}".format(sock_type=type))
        if port == 0 or port is None:
            port = 53

        if (self.thread is None):
            self.thread = threading.Thread(target=self.query_io)
            self.thread.start()

        for srv_sock in self.srv_socks:
            if srv_sock.family == family and srv_sock.client_address == address :
                return srv_sock.getsockname()
    
        addr_info = socket.getaddrinfo(address,port,family,0,socket.IPPROTO_UDP)
        sock = SrvSock(address, family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        addr_info_entry0 = addr_info[0]
        sockaddr = addr_info_entry0[4]
        sock.bind(sockaddr)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_socks.append(sock)
        sockname = sock.getsockname()
        return sockname

    def play(self):
        saddr = get_local_addr_str(socket.AF_INET,self.default_iface)
        paddr = get_local_addr_str(socket.AF_INET,self.peer_iface)
        self.scenario.play(saddr,paddr)

if __name__ == '__main__':
    # Self-test code
    DEFAULT_IFACE = 0
    CHILD_IFACE = 0
    if "SOCKET_WRAPPER_DEFAULT_IFACE" in os.environ:
       DEFAULT_IFACE = int(os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"])
    if DEFAULT_IFACE < 2 or DEFAULT_IFACE > 254 :
        DEFAULT_IFACE = 10
        os.environ["SOCKET_WRAPPER_DEFAULT_IFACE"]="{}".format(DEFAULT_IFACE)
    # Mirror server
    server = TestServer(None,None,DEFAULT_IFACE,DEFAULT_IFACE)
    server.start()
    print "[==========] Mirror server running at", server.address()
    try:
        while True:
	    time.sleep(0.5)
    except KeyboardInterrupt:
        print "[==========] Shutdown."
        pass
    server.stop()
