.. SPDX-License-Identifier: GPL-3.0-or-later

.. _rfc-list:

List of RFCs
============

Here we provide a list of implemented RFCs, though it may not be 100% complete.
Normal users shouldn't need to look here; they might search the docs instead.

Note that in some cases only part of the RFC is covered,
as some parts are optional to a degree or even not relevant to DNS resolvers.


:rfc:`1034`
    Domain Names – Concepts and Facilities
:rfc:`1035`
    Domain Names – Implementation and Specifciation
:rfc:`1101`
    DNS Encoding of Network Names and Other Types
:rfc:`1123`
    Requirements for Internet Hosts -- Application and Support
..
 I haven't heard of anyone using these RR types in the past decade.
 :rfc:`1183`
    New DNS RR Definitions
..
 Uh, why?  TCP implementation details are for OS to deal with, not us.
 :rfc:`13371
    TIME-WAIT Assassination Hazards in TCP

.. Uh well, our DoH server does use MIME, I guess...
:rfc:`1521`
    MIME (Multipurpose Internet Mail Extensions) Part One: Mechanisms for Specifying and Describing the Format of Internet Message Bodies
..
 I haven't heard of anyone using these RR types in the past decade.
 :rfc:`1706`
    DNS NSAP Resource Records
 :rfc:`1712`
    DNS Encoding of Geographical Location
:rfc:`1876`
    A Means for Expressing Location Information in the Domain Name System
..
 I don't think we're really utilizing it in resolver right now.  In Knot DNS for sure, but...
 :rfc:`1982`
    Serial Number Arithmetic
..
 No *XFR yet in resolver.
 :rfc:`1995`
    Incremental Zone Transfer in DNS
 :rfc:`1996`
    A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
..
 Large RFC about an obsolete mechanism.
 KNOT_RRTYPE_PX exists, but just for name compression to work,
 so I don't think we can claim this RFC as supported really.
 :rfc:`2163`
    Using the Internet DNS to Distribute MIXER Conformant Global Address Mapping (MCGAM)

:rfc:`2181`
    Clarifications to the DNS Specification
..
 I fail to see how one could call this RFC supported by any kind of resolver.
 :rfc:`2182`
    Selection and Operation of Secondary DNS Servers
:rfc:`2230`
    Key Exchange Delegation Record for the DNS
..
 I fail to see how representation of names in LDAP is related.
 :rfc:`2253`
    Lightweight Directory Access Protocol (v3): UTF-8 String Representation of Distinguished Names
:rfc:`2308`
    Negative Caching of DNS Queries (DNS NCACHE)
:rfc:`2535`
    Domain Name System Security Extensions

    *This variant of DNSSEC has been obsolete for many years, but we stil support those RRs (in zonefile and wire).*
..
 DSA crypto has been obsoleted.
 :rfc:`2536`
    DSA KEYs and SIGs in the Domain Name System (DNS)
..
 MD5-based crypto has been obsoleted.
 :rfc:`2537`
    RSA/MD5 KEYs and SIGs in the Domain Name System (DNS)
:rfc:`2538`
    Storing Certificates in the Domain Name System (DNS)

    *The RFC is obsolete, but we still support those RRs (in zonefile and wire).*
..
 DH in DNSSEC has been long obsolete.
 :rfc:`2539`
    Storage of Diffie-Hellman Keys in the Domain Name System (DNS)
:rfc:`2606`
    Reserved Top Level DNS Names
:rfc:`2671`
    Extension Mechanisms for DNS (EDNS0)

    *Well, the EDNS0 definition has been rewritten as* :rfc:`6891` *which we really support.*
:rfc:`2672`
    Non-Terminal DNS Name Redirection

    *Well, the DNAME definition has been rewritten as* :rfc:`6672` *which we really support.*
..
 This has been obsoleted over a decade ago, and I'm not sure if it works for us.
 :rfc:`2673`
    Binary Labels in the Domain Name System
:rfc:`2782`
    A DNS RR for specifying the location of services (DNS SRV)
..
 A6 is obsolete/historic, and we don't even support the type anymore (in zonefile and wire).
 :rfc:`2874`
    DNS Extensions to Support IPv6 Address Aggregation and Renumbering
:rfc:`2915`
    The Naming Authority Pointer (NAPTR) DNS Resource Record
..
 I don't think we can call this supported.  Name (de)compression for TKEY yes, but not even zonefile.
 :rfc:`2930`
    Secret Key Establishment for DNS (TKEY RR)
..
 This is for KEY and SIG records; see the same as :rfc:`2535` above.
 :rfc:`3110`
    RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System (DNS)
:rfc:`3123`
    A DNS RR Type for Lists of Address Prefixes (APL RR)

    *This is probably unused in practice, but we still support the APL RR (in zonefile and wire).*
:rfc:`3225`
    Indicating Resolver Support of DNSSEC

    *This is the* **DO** *bit in DNS messages.*

.. This is most likely still part of normal DH handshake in TLS, though I expect that newer exchange is negotiated typically nowadays.
:rfc:`3526`
    More Modular Exponential (MODP) Diffie-Hellman groups for Internet Key Exchange (IKE)
:rfc:`3597`
    Handling of Unknown DNS Resource Record (RR) Types
..
 TODO I'm not sure.  Maybe gnutls does implement this certificate stuff and then we could profess compliance.
 :rfc:`3779`
    X.509 Extensions for IP Addresses and AS Identifiers

.. We can listen on scoped IPv6 addresses.
:rfc:`4007`
    IPv6 Scoped Address Architecture
:rfc:`4025`
    A Method for Storing IPsec Keying Material in DNS
:rfc:`4033`
    DNS Security Introduction and Requirements
:rfc:`4034`
    Resource Records for the DNS Security Extensions
:rfc:`4035`
    Protocol Modifications for the DNS Security Extensions
:rfc:`4255`
    Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
:rfc:`4343`
    Domain Name System (DNS) Case Insensitivity Clarification
:rfc:`4398`
    Storing Certificates in the Domain Name System (DNS)
..
 DLV is long obsolete/historic, and we don't even support the type anymore (in zonefile and wire).
 :rfc:`4431`
    The DNSSEC Lookaside Validation (DLV) DNS Resource Record
:rfc:`4509`
    Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)
:rfc:`4592`
    The Role of Wildcards in the Domain Name System
..
 Uh, no idea how this is related to DNS.
 :rfc:`4597`
    Conferencing Scenarios
:rfc:`4697`
    Observed DNS Resolution Misbehavior
:rfc:`4701`
    A DNS Resource Record (RR) for Encoding Dynamic Host Configuration Protocol (DHCP) Information (DHCID RR)
:rfc:`5001`
    DNS Name Server Identifier (NSID) Option
    
    *See* :ref:`config-nsid`
:rfc:`5011`
    Automated Updates of DNS Security (DNSSEC) Trust Anchors

    *See inside* :ref:`config-dnssec`

.. Same as 3526.
:rfc:`5114`
    Additional Diffie-Hellman Groups for Use with IETF Standards
:rfc:`5155`
    DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
..
 HIP is long obsolete/historic, and we don't even support the type anymore (in zonefile and wire).
 :rfc:`5205`
    Host Identity Protocol (HIP) Domain Name System (DNS) Extension
:rfc:`5358`
    Preventing Use of Recursive Nameservers in Reflector Attacks
:rfc:`5452`
    Measures for Making DNS More Resilient against Forged Answers
:rfc:`5702`
    Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
..
 This crypto-protocol is obsolete, and I believe we've never supported it.
 :rfc:`5933`
    Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC
..
 I don't know.  NAT64 doesn't seem related except for DNS64 which follows directly.
 :rfc:`6146`
    Stateful NAT64: Network Address and Protocol Translation from IPv6 Clients to IPv4 Servers
:rfc:`6147`
    DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers

    *See* :ref:`config-dns64`
:rfc:`6234`
    US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
:rfc:`6303`
    Locally Served DNS Zones
:rfc:`6598`
    IANA-Reserved IPv4 Prefix for Shared Address Space
:rfc:`6604`
    xNAME RCODE and Status Bits Clarification
:rfc:`6605`
    Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
:rfc:`6672`
    DNAME Redirection in the DNS
:rfc:`6698`
    The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA

    *We support the record, but not authenticating by it.*
:rfc:`6725`
    DNS Security (DNSSEC) DNSKEY Algorithm IANA Registry Updates
:rfc:`6742`
    DNS Resource Records for the Identifier-Locator Network Protocol (ILNP)
:rfc:`6761`
    Special-Use Domain Names
:rfc:`6840`
    Clarifications and Implementation Notes for DNS Security (DNSSEC)
:rfc:`6844`
    DNS Certification Authority Authorization (CAA) Resource Record
:rfc:`6891`
    Extension Mechanisms for DNS (EDNS(0))
..
 We've never implemented this one and it's never gotten popularity.
 :rfc:`6975`
    Signaling Cryptographic Algorithm Understanding in DNS Security Extensions (DNSSEC)
:rfc:`7043`
    Resource Records for EUI-48 and EUI-64 Addresses in the DNS
:rfc:`7344`
    Automating DNSSEC Delegation Trust Maintenance
:rfc:`7413`
    TCP Fast Open

    *We only support it on the server side.*
:rfc:`7477`
    Child-to-Parent Synchronization in DNS
:rfc:`7553`
    The Uniform Resource Identifier (URI) DNS Resource Record
:rfc:`7646`
    Definition and Use of DNSSEC Negative Trust Anchors

    *See inside* :ref:`config-dnssec`
:rfc:`7686`
    The ".onion" Special-Use Domain Name
:rfc:`7706`
    Decreasing Access Time to Root Servers by Running One on Loopback

    *Obsoleted by* :rfc:`8806`; *see also* :ref:`config-cache-prefill`
:rfc:`7766`
    DNS Transport over TCP - Implementation Requirements
:rfc:`7830`
    The EDNS(0) Padding Option

    *See inside* :ref:`config-network-server-tls`
:rfc:`7858`
    Specification for DNS over Transport Layer Security (TLS)

    *See* :ref:`dns-over-tls` *and* :ref:`config-forward`.
..
 We currently don't plan ECS.
 :rfc:`7871`
    Client Subnet in DNS Queries
..
 Cookies are a missing feature so far, though some older code exists.
 :rfc:`7873`
    Domain Name System (DNS) Cookies
:rfc:`7929`
    DNS-Based Authentication of Named Entities (DANE) Bindings for OpenPGP
:rfc:`7958`
    DNSSEC Trust Anchor Publication for the Root Zone

    *Though typical Knot Resolver packaging uses a different approach.*
..
 I don't think we can claim this as fully supported,
 as our cache so far does not work that way
 (except for aggressive DNSSEC caching, but that's different really).
 :rfc:`8020`
    NXDOMAIN: There Really Is Nothing Underneath
:rfc:`8080`
    Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC
:rfc:`8145`
    Signaling Trust Anchor Knowledge in DNS Security Extensions (DNSSEC)

    *See* :ref:`config-ta-signal-query`
:rfc:`8162`
    Using Secure DNS to Associate Certificates with Domain Names for S/MIME
:rfc:`8198`
    Aggressive Use of DNSSEC-Validated Cache

    *See* :ref:`config-cache`
:rfc:`8310`
    Usage Profiles for DNS over TLS and DNS over DTLS
:rfc:`8375`
    Special-Use Domain 'home.arpa.'
:rfc:`8467`
    Padding Policies for Extension Mechanisms for DNS (EDNS(0))

    *See inside* :ref:`config-network-server-tls`
:rfc:`8482`
    Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY

    *This RFC was focused on authoritative servers.
    As a resolver, we shouldn't just make up data on arbitrary names,
    so we really use a different minimization method currently: reply with RCODE=NOTIMPL.*
:rfc:`8484`
    DNS Queries over HTTPS (DoH)

    *See* :ref:`dns-over-https`
:rfc:`8509`
    A Root Key Trust Anchor Sentinel for DNSSEC

    *See* :ref:`config-ta_sentinel`
:rfc:`8624`
    Algorithm Implementation Requirements and Usage Guidance for DNSSEC
:rfc:`8767`
    Serving Stale Data to Improve DNS Resiliency

    *See* :ref:`config-serve-stale`
:rfc:`8806`
    Running a Root Server Local to a Resolver

    *See* :ref:`config-cache-prefill`
:rfc:`8914`
    Extended DNS Errors
:rfc:`8976`
    Message Digest for DNS Zones
..
 Cookies are a missing feature so far, though some older code exists.
 :rfc:`9018`
    Interoperable Domain Name System (DNS) Server Cookies
:rfc:`9077`
    NSEC and NSEC3: TTLs and Aggressive Use
:rfc:`9156`
    DNS Query Name Minimisation to Improve Privacy

    *Our current code doesn't use full minimization but a compromise approach,
    which in practice mainly minimizes queries going to root and TLD servers.
    We also have a fallback that deals with typical cases of non-conforming servers.*
:rfc:`9210`
    DNS Transport over TCP - Operational Requirements
.. No DoQ yet, but it's planned.
 :rfc:`9250`
    DNS over Dedicated QUIC Connections
