Layered protocols
=================

Motivation
----------

One of the bigger changes made in Knot Resolver 6 is the almost complete
rewrite of its I/O (input/output) system and management of communication
sessions.

To understand why this rewrite was needed, let us first take a brief
look at the history of Knot Resolver’s I/O.

In the beginning, the Resolver’s I/O was really quite simple. As it only
supported DNS over plain UDP and TCP (nowadays collectively called Do53
after the standardized DNS port), there used to be only two quite
distinct code paths for communication – one for UDP and one for TCP.

As time went on and privacy became an important concern in the internet
community, we gained two more standardized transports over which DNS
could be communicated: TLS and HTTPS. Both of these run atop TCP, with
HTTPS additionally running on top of TLS. It thus makes sense that all
three share some of the code relevant to all of them. However, up until
the rewrite, all three transports were quite entangled in a single big
mess of code, making the I/O system increasingly harder to maintain as
the Resolver was gaining more and more I/O-related features (one of the
more recent ones pertaining to that part of the code being the support for the
`PROXY protocol <https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt>`__).

Another aspect that led to the decision to ultimately rewrite the whole
thing was the plan to add support for *DNS-over-QUIC* (DoQ). QUIC is a
special kind of beast among communication protocols. It runs on top of
**UDP**, integrates TLS, and – unlike TCP, where each connection creates
only a single stream – it can create *multiple independent streams in a
single connection*. This means that, with only a single TLS handshake
(which is a very costly part of any connection establishment routine),
one can create multiple streams of data that do not have to wait for
each other [1]_, which allows for theoretically very efficient encrypted
communication. On the other hand, it also means that Knot Resolver was
increasingly ill-prepared for the future, because there was no way the
status quo could accommodate such connections.

Enter the rewrite. One of the goals of this effort was to prepare Knot
Resolver for the eventual implementation of QUIC, as well as to untangle
its I/O system and make it easier to maintain and reason about in
general. But before we start rewriting, we first need to get to
understand *sessions*.

Sessions, tasks, wire buffers, protocol ceremony
------------------------------------------------

Knot Resolver has long been using the concept of so-called *sessions*. A
session is a data structure (``struct session``) generally holding
information about a connection in the case of TCP, some shared
information about the listening socket in the case of incoming UDP, or
information about I/O towards an authoritative DNS server in the case of
outgoing UDP. This information includes, among other things, a bit field
of flags, which tell us whether the session is *outgoing* (i.e. towards
an authoritative server, instead of a client), whether it has been
*throttled*, whether the connection has been established (or is yet
waiting to be established), and more. Historically, in Knot Resolver
<=5, it also contained information about whether TLS and/or HTTPS was
being used for a particular session.

Sessions also keep track of so-called *query resolution tasks*
(``struct qr_task``) – these can be thought of as units of data about a
query that is being resolved, either *incoming* (i.e. from a client) or
*outgoing* (i.e. to an authoritative server). As it is not unusual for
tasks to be relevant to multiple sessions (a client or even multiple
ones asking the same query, the authoritative servers that are being
consulted for the right answer), they are reference-counted, and their
lifetime may at times look quite blurry to the programmer, since we
refer to them from multiple places (e.g. the sessions, I/O handles,
timers, etc.). If we get the reference counting wrong, we may either
free a task’s memory too early, or we may get a dangling task –
basically a harder-to-catch memory leak. Since there usually is
*something* pointing to the task, common leak detectors will not be able
find such a leak.

In addition to this, a session also holds a *wire buffer* – this is a
fixed-length buffer we fill with DNS queries in the binary format
defined by the DNS standard (called the *wire format*, hence the name
*wire buffer*). This buffer is kept per-connection for TCP and
per-endpoint for UDP and (a portion of it) is passed to the ``libuv``
library for the operating system to write the data into during
asynchronous I/O operations.

The wire buffer is used for **input** and is controlled by two indices –
*start* and *end*. These tell us which parts of the wire buffer contain
valid but as of yet unprocessed data. In UDP, we get the whole DNS
message at once, together with its length, so this mechanism is not as
important there; but in TCP, we only get the concept of a contiguous
stream of bytes in the user space. There is no guarantee in how much of
a DNS message we get on a single receive callback, so it is common that
DNS messages need to be *pieced together*.

In order to parse DNS messages received over TCP, we need two things:
the DNS standard-defined 16-bit message length that is prepended to each
actual DNS message in a stream; and a buffer into which we continuously
write our bytes until we have the whole message. With the *end* index,
we can keep track of where in the buffer we are, appending to the end of
what has already been written. This way we get the whole DNS message
even if received piecewise.

But what about the *start* index? What is *that* for? Well, we can use
it to strip protocol “ceremony” from the beginning of the message. This
may be the 16-bit message length, a PROXY protocol header, or possibly
other data. This ceremony stripping allows us to eventually pass the
whole message to the exact same logic that processes UDP DNS messages,
once we are done with all of it.

This is however not the whole story of ceremony stripping. As mentioned,
in TCP there are two more protocols that share this same code path, and
those are *DNS-over-TLS* (DoT) and *DNS-over-HTTPS* (DoH). For TLS and
HTTP/2 (only the first one in the case of DoT, and both together in the
case of DoH), we need to *decode* the buffer and store the results in
*another* buffer, since the ceremony is not simply prepended to the rest
of the message, but it basically transforms its whole content.

Now, for **output**, the process is quite similar, just in reverse – We
prepend the 16-bit message length and encode the resulting bytes using
HTTP/2 and/or TLS. To save us some copying and memory allocations, we
actually do not need to use any special wire buffer or other contiguous
memory area mechanism. Instead, we leverage I/O vectors
(``struct iovec``) defined by POSIX, through which we basically provide
the OS with multiple separate buffers and only tell it which order these
buffers are supposed to be sent in.

Isolation of protocols
----------------------

Let us now look at Knot Resolver from another perspective. Here is what
it generally does from a very high-level point of view: it takes a
client’s *incoming* DNS query message from the I/O, parses it and
figures out what to do to resolve it (i.e. either takes the answer from
the cache, or *asks around* in the network of authoritative servers [2]_
– utilizing the I/O again, but with an *outgoing* DNS query). Then it
puts together an answer and hands it back over to the I/O towards the
client. This basic logic is (mostly) the same for all types of I/O – it
does not matter whether the request came through Do53, DoH, DoT, or DoQ,
this core part will always do the same thing.

As already indicated, the I/O basically works in two directions:

-  it either takes the wire bytes and transforms them into something the
   main DNS resolver decision-making system can work with (i.e. it
   strips them of the “ceremony” imposed by the protocols used) – we
   call this the *unwrap direction*;
-  or it takes the resolved DNS data and transforms it back into the
   wire format (i.e. adds the imposed “ceremony”) – we call this the
   *wrap direction*.

If we look at it from the perspective of the OSI model [3]_, in the
*unwrap direction* we climb *up* the protocol stack; in the *wrap
direction* we step *down*.

It is also important to note that the code handling each of the
protocols may for the most part only be concerned with its own domain.
PROXYv2 may only check the PROXY header and modify transport
metadata [4]_; TLS may only take care of securing the connection,
encrypting and decrypting input bytes; HTTP/2 may only take care of
adding HTTP metadata (headers, methods, etc.) and encoding/decoding the
data streams; etc. The protocols basically do not have to know much of
anything about each other, they only see the input bytes without much
context, and transform them into output bytes.

Since the code around protocol management used to be quite tangled
together, it required us to jump through hoops in terms of resource
management, allocating and deallocating additional buffers required for
decoding in ways that are hard to reason about, managing the
aforementioned tasks and their reference-counting, which may be very
error-prone in unmanaged programming languages like C, where the
counting needs to be done manually.

Asynchronous I/O complicates this even further. Flow control is not
“straight-through” as with synchronous I/O, which meant that we needed
to wait for finishing callbacks, the order of which may not always be
reliably predictable, to free some of the required resources.

All of this and more makes the lifecycles of different resources and/or
objects rather unclear and hard to think about, leading to bugs that are
not easy to track down.

To clear things up, we have decided to basically tear out most of the
existing code around sessions and transport protocols and reimplement it
using a new system we call *protocol layers*.

Protocol layers
---------------

.. note::

    For this next part, it may be useful to open up the
    `Knot Resolver sources <https://gitlab.nic.cz/knot/knot-resolver>`__,
    find the ``daemon/session2.h`` and ``daemon/session2.c`` files and use them
    as a reference while reading this post.

In Knot Resolver 6, protocols are organized into what are basically
virtual function tables, sort of like in the object-oriented model of
C++ and other languages. There is a ``struct protolayer_globals``
defining a protocol’s interface, mainly pointers to functions that are
responsible for state management and the actual data transformation, and
some other metadata, like the size of a layer’s state struct. It is
basically what you would call a table of virtual functions in an
object-oriented programming language.

Layers are organized in *sequences* (static arrays of
``enum protolayer_type``). A sequence is based on what the *high-level
protocol* is; for example, DNS-over-HTTPS, one of the high-level
protocols, has a sequence of these five lower-level protocols, in
*unwrap* order: TCP, PROXYv2, TLS, HTTP, and DNS.

This is then utilized by a layer management system, which takes a
*payload* – i.e. a chunk of data – and loops over each layer in the
sequence, passing said payload to the layer’s *unwrap* or *wrap*
callbacks, depending on whether the payload is being received from the
network or generated and sent by Knot Resolver, respectively (as
described above). The ``struct protolayer_globals`` member callbacks
``unwrap`` and ``wrap`` are responsible for the transformation itself,
each in the direction to which its name alludes.

Also note that the order of layer traversal is – unsurprisingly –
reversed between *wrap* and *unwrap* directions.

This is the basic idea of protocol layers – we take a payload and
process it with a pipeline of layers to be either sent out, or processed
by Knot Resolver.

The layer management system also permits any layer to interrupt the
payload processing, basically switching between synchronous to
asynchronous operation. Layers may produce payloads without being
prompted to by a previous layer as well.

Both of these are necessary because in some layers, like HTTP and TLS,
input and output payloads are not always in a one-to-one relationship,
i.e. we may need to receive multiple input payloads for HTTP to produce
an output payload. Some layers may also need to produce payloads without
having received *any* input payloads, like when there is an ongoing TLS
handshake. An upcoming *query prioritization* feature also utilizes the
interruption mechanism to defer the processing of payloads to a later
point in time.

Apart from the aforementioned callbacks, layers may define other
parameters. As mentioned, layers are allowed to declare their custom
state structs, both per-session and/or per-payload, to hold their own
context in, should they need it. There are also callbacks for
initialization and deinitialization of the layer, again per-session
and/or per-payload, which are primarily meant to (de)initialize said
structs, but may well be used for other preparation tasks. There is also
a simple system in place for handling events that may occur, like
session closure (both graceful and forced), timeouts, OS buffer
fill-ups, and more.

Defining a protocol
~~~~~~~~~~~~~~~~~~~

A globals table for HTTP may look something like this:

.. code:: c

   protolayer_globals[PROTOLAYER_TYPE_HTTP] = (struct protolayer_globals){
       .sess_size = sizeof(struct pl_http_sess_data),
       .sess_deinit = pl_http_sess_deinit,
       .wire_buf_overhead = HTTP_MAX_FRAME_SIZE,
       .sess_init = pl_http_sess_init,
       .unwrap = pl_http_unwrap,
       .wrap = pl_http_wrap,
       .event_unwrap = pl_http_event_unwrap,
       .request_init = pl_http_request_init
   };

Note that this is using the `C99 compound literal syntax
<https://en.cppreference.com/w/c/language/compound_literal>`__,
in which unspecified members are set to zero. The interface is designed
so that all of its parts may be specified on an as-needed basis – all of
its fields are optional and zeroes are a valid option [5]_. In the case
illustrated above, HTTP uses almost the full interface, so most members
in the struct are populated. The PROXYv2 implementations (separate
variants for UDP and TCP) on the other hand, are quite simple, only
requiring ``unwrap`` handlers and tiny structs for state:

.. code:: c

   // Note that we use the same state struct for both DGRAM and STREAM, but in
   // DGRAM it is per-iteration, while in STREAM it is per-session.

   protolayer_globals[PROTOLAYER_TYPE_PROXYV2_DGRAM] = (struct protolayer_globals){
       .iter_size = sizeof(struct pl_proxyv2_state),
       .unwrap = pl_proxyv2_dgram_unwrap,
   };

   protolayer_globals[PROTOLAYER_TYPE_PROXYV2_STREAM] = (struct protolayer_globals){
       .sess_size = sizeof(struct pl_proxyv2_state),
       .unwrap = pl_proxyv2_stream_unwrap,
   };

Transforming payloads
~~~~~~~~~~~~~~~~~~~~~

Let us now look at the ``wrap`` and ``unwrap`` callbacks. They are both
of the same type, ``protolayer_iter_cb``, specified by the following C
declaration:

.. code:: c

   typedef enum protolayer_iter_cb_result (*protolayer_iter_cb)(
           void *sess_data,
           void *iter_data,
           struct protolayer_iter_ctx *ctx);

A function of this type takes two ``void *`` pointers pointing to
layer-specific state structs, as allocated according to the
``sess_size`` and ``iter_size`` members of ``protolayer_globals``. for
the currently processsed layer. These have a *session* lifetime and
so-called *iteration* lifetime, respectively. An *iteration* here is
what we call the process of going through a sequence of protocol layers,
transforming a payload one-by-one until either an internal system is
reached (in the *unwrap* direction), or the I/O is used to transfer said
payload (in the *wrap* direction). Iteration-lifetime structs are
allocated and initialized when a new payload is constructed, and are
freed when its processing ends. Session-lifetime structs are allocated
and initialized, and then later deinitialized together with each
session.

A struct pointing to the payload lives in the ``ctx`` parameter of the
callback. This context lives through the whole *iteration* and contains
data useful for both the system managing the protocol layers as a whole,
and the implementations of individual layers, which actually includes
the memory pointed to by ``iter_data`` (but the pointer is provided both
as an optimization *and* for convenience). The rules for manipulating
the ``struct protolayer_iter_ctx`` in a way so that the whole system
works in a defined manner are specified in its comments in the
``session2.h`` file.

You may have noticed that the callbacks’ return value,
``enum protolayer_iter_cb_result``, has actually only a single value,
the ``PROTOLAYER_ITER_CB_RESULT_MAGIC``, with a random number. This
value is there only for sanity-checking. When implementing a layer, you
are meant to exit the callbacks with something we call *layer sequence
return functions*, which dictate how the control flow of the iteration
is meant to continue:

-  ``protolayer_continue`` tells the system to simply pass the current
   payload on to the next layer, or the I/O if this is the last layer.
-  ``protolayer_break`` tells the system to end the iteration on the
   current payload, with the specified status code, which is going to be
   logged in the debug log. The status is meant to be one of the
   POSIX-defined ``errno`` values.
-  ``protolayer_async`` tells the system to interrupt the iteration on
   the current payload, to be *continued* and/or *broken* at a later
   point in time. The planning of this is the responsibility of the
   layer that called the ``protolayer_async`` function – this gives the
   layer absolute control of what is going to happen next, but, if not
   done correctly, leaks will occur.

This system clearly defines the lifetime of
``struct protolayer_iter_ctx`` and consequently all of its associated
resources. The system creates the context when a payload is submitted to
the pipeline, and destroys it either when ``protolayer_break`` is
called, or the end of the layer sequence has been reached (including
processing by the I/O in the *wrap* direction).

When submitting payloads, the submitter is also allowed to define a
callback for when the iteration has ended. This callback is called for
**every** way the iteration may end (except for undetected leaks), even
if it immediately fails, allowing for fine-grained control over
resources with only a minimum amount of checks that need to be in place
at the submitter site.

To implement a payload transform for a protocol, you simply modify the
provided payload. Note that the memory a payload points to is always
owned by the system that had created it, so if a protocol requires extra
resources for its transformation, it needs to manage it by itself.

The ``struct protolayer_iter_ctx`` provides a convenient ``pool``
member, using the ``knot_mm_t`` interface from Knot DNS. This can be
used by layers to allocate additional memory, which will get freed
automatically at the end of the context’s lifetime. If a layer has any
special needs regarding resource allocation, it needs to take proper
care of it by itself (preferably using its state struct), and free all
of its allocated resources by itself in its deinitialization callbacks.

Events
~~~~~~

There is one more important aspect to protocol layers. Apart from
payload transformation, the layers occasionally need to get to know
and/or let other layers know of some particular *events* that may occur.
Events may let layers know that a session is about to close, or is being
closed “forcefully” [6]_, or something may have timed out, a malformed
message may have been received, etc.

The event system is similar to payload transformation in that it
iterates over layers in ``wrap`` and ``unwrap`` directions, but the
procedure is simplified quite a bit. We may never choose, which
direction we start in – we always start in ``unwrap``, then
automatically bounce back and go in the ``wrap`` direction. Event
handling is also never asynchronous and there is no special context
allocated for event iterations.

Each ``event_wrap`` and/or ``event_unwrap`` callback may return either
``PROTOLAYER_EVENT_CONSUME`` to consume the event, stopping the
iteration; or ``PROTOLAYER_EVENT_PROPAGATE`` to propagate the event to
the next layer in sequence. The default (when there is no callback) is
to propagate; well-behaved layers will also propagate all events that do
not concern them.

This provides us with a degree of abstraction – e.g. when using
DNS-over-TLS towards an upstream server (currently only in forwarding),
from the point of view of TCP a connection may have been established, so
the I/O system sends a ``CONNECT`` event. This would normally (in plain
TCP) signal the DNS layer to start sending queries, but TLS still needs
to perform a secure handshake. So, TLS consumes the ``CONNECT`` event
received from TCP, performs the handshake, and when it is done, it sends
its own ``CONNECT`` event to subsequent layers.

.. [1]
   Head-of-line blocking:
   https://en.wikipedia.org/wiki/Head-of-line_blocking

.. [2]
   Plus DNSSEC validation, but that does not change this process from
   the I/O point of view much either.

.. [3]
   Open Systems Interconnections model – a model commonly used to
   describe network communications.
   (`Wikipedia <https://en.wikipedia.org/wiki/OSI_model>`__)

.. [4]
   The metadata consists of IP addresses of the actual clients that
   queried the resolver through a proxy using the PROXYv2 protocol – see
   the relevant
   `documentation <https://www.knot-resolver.cz/documentation/latest/config-network-server.html#proxyv2-protocol>`__.

.. [5]
   This neat pattern is sometimes called *ZII*, or *zero is
   initialization*, `as coined by Casey
   Muratori <https://www.youtube.com/watch?v=lzdKgeovBN0&t=1684s>`__.

.. [6]
   The difference between a forceful close and a graceful one is that
   when closing gracefully, layers may still do some ceremony
   (i.e. inform the other side that the connection is about to close).
   With a forceful closure, we just stop communicating.
