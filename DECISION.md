# Design Decisions

This document chronicles the architectural evolution of the project, detailing the rationale behind critical design choices, alternative paths evaluated, and explicit trade-offs accepted.

## Decision 1: From a single-threaded synchronous blocking model to a multi-threaded concurrent architecture

**Context & core milestone**

Early prototype validation stage. To verify network feasibility, the initial scanner used a sequential single-threaded blocking loop. However, scanning latency was unacceptable for mass-port probing.

**Alternatives evaluated**

- Option A: Continue using the single-threaded synchronous blocking iteration.
- Option B: Re-architect the application into a concurrent multi-threaded framework.

**Rationale (why Option B?)**

Option A suffers from severe CPU idle periods because the single thread blocks waiting for each port's timeout or handshake. Option B leverages OS thread scheduling to overlap network latency across multiple ports, minimising I/O blocking bottlenecks and expanding scanning throughput.

**Design trade-offs & sacrifices**

- Complexity & data integrity: moving away from deterministic linear execution introduced the risk of data races on shared memory (the `open_ports` vector). This required synchronisation primitives (`mutex`), which introduced a second threat: lock contention (see [DEV_LOG.md](DEV_LOG.md)).
- Protocol footprint (unchanged constraint): because the application still relied on standard OS stream sockets (`SOCK_STREAM`), it remained bound to full TCP three-way handshakes, leaving obvious traces in the target hosts' logs. This led to Decision 2.

## Decision 2: From `connect()` scanning to a raw-socket SYN scan

**Context**

A `connect()` scan lets the kernel perform a full three-way handshake for every port. Each probe opens and closes a real connection, and the program can't see or control the packets involved.

**Alternatives evaluated**

- Option A: Keep the `connect()` scanner. It is portable and needs no special privileges.
- Option B: Build the IPv4 and TCP headers by hand and send a single SYN through a raw socket (`SOCK_RAW` with `IP_HDRINCL`), then read the SYN-ACK or RST directly.

**Rationale (why Option B?)**

One packet per port is enough to learn whether it is open, and the handshake is never completed, so the target's services never see a connection. Building the packets by hand also meant working with the protocols at byte level (struct packing, byte order, the Internet checksum and the TCP pseudo-header), which was the main learning goal of the project.

**Design trade-offs & sacrifices**

- Raw sockets need root or `CAP_NET_RAW`, and the code became Linux-specific.
- The program must compute the TCP checksum itself; one wrong byte and the target silently drops the packet. The packets were checked in Wireshark.
- The kernel no longer matches replies to probes, so the program has to do it (Decision 3).

## Decision 3: Separate sender and receiver threads, with `select()` on the receiving side

**Context**

The first SYN scanner was a single-threaded loop: send one SYN, wait for the reply (with a `SO_RCVTIMEO` timeout), move to the next port. That brought back the per-port waiting that Decision 1 had removed.

**Alternatives evaluated**

- Option A: Keep send-then-wait in one thread.
- Option B: One side sends probes for all ports while a dedicated receiver thread continuously reads replies and matches them to probes.

**Rationale (why Option B?)**

Sending no longer waits for any reply, so the time for a whole scan is roughly the send time plus one final wait for late replies, instead of the sum of every port's wait. The receiver thread is started before sending begins, so even the fastest replies are caught. It waits with `select()` and a 1-second timeout rather than a plain blocking `recvfrom()`. It sleeps until a packet arrives, but still wakes up regularly to check the `atomic<bool>` stop flag, so the program can always shut down cleanly.

**Design trade-offs & sacrifices**

- Replies must be matched to probes by their fields: destination port equal to our source port, acknowledgement number equal to our sequence number + 1, and source IP equal to the target.
- The results vector is now shared between threads and needs a mutex.
- After sending, the program has to guess how long to wait for late replies (a fixed 500 ms). A slower network can need more.

## Decision 4: A fixed worker pool fed by a shared port queue

**Context**

The next step was sending with multiple threads. Splitting the port range into fixed chunks per thread, or creating one thread per port, either balances work poorly or creates an unbounded number of threads.

**Alternatives evaluated**

- Option A: Give each thread a fixed slice of the port range.
- Option B: A fixed number of worker threads (`-t`) that take ports from one shared `std::queue`, coordinated with a `mutex` and a `condition_variable` (producer–consumer).

**Rationale (why Option B?)**

The number of threads stays bounded no matter how many ports are scanned. Work is balanced automatically, because a worker that finishes early just takes the next port. Workers sleep on the condition variable instead of spinning, and they exit cleanly once the queue is empty and the producer has marked every port as added.

**Design trade-offs & sacrifices**

- Every port costs one lock/unlock of the queue mutex.
- Later measurement showed that for a SYN scan, extra sender threads give only a small speed-up, because `sendto()` never waits for a handshake. Sending at full speed also exposed a packet-loss bug (Decision 5).

## Decision 5: Enlarging the raw socket's receive buffer

**Context**

Testing against known open ports showed that with 4 or more sender threads the scanner silently missed open ports. Replies were arriving faster than the receiver thread could read them, and the kernel dropped packets once the socket's ~200 KB receive buffer was full (details and measurements in [DEV_LOG.md](DEV_LOG.md)).

**Alternatives evaluated**

- Option A: Use a single sender thread, or bring back a fixed delay between probes.
- Option B: Add proper rate limiting and retransmission of unanswered probes.
- Option C: Enlarge the receive buffer to 32 MB with `SO_RCVBUFFORCE`, falling back to `SO_RCVBUF`.

**Rationale (why Option C?)**

It is a small, local change that removed the loss in every tested configuration (1–64 threads, up to all 65,535 ports) without slowing the scan down. Option A gives up speed, and Option B is the more complete solution but a much larger change.

**Design trade-offs & sacrifices**

- The kernel may hold up to 32 MB of queued packets for this socket during a scan.
- Without root, `SO_RCVBUF` is capped by `net.core.rmem_max`, and the loss can come back when many threads are used.
- A bigger buffer only fixes loss inside this machine. Probes or replies dropped on the network are still not retransmitted (Option B remains future work).
