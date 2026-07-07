This document chronicles the architectural evolution of the project, detailing the rationales behind critical design choices, alternative paths evaluated, and explicit trade-offs accepted. Strictly limited to 1 page.



Decision 1: Transitioning from a Single-Threaded Synchronous Blocking Model to a Multi-Threaded Concurrent Architecture



*Context \& Core Milestone*

Early prototype validation stage. To verify network feasibility, the initial scanner utilized a sequential single-threaded blocking loop. However, scanning latency was unacceptable for mass-port probing.



Alternatives Evaluated

* Option A: Continue using the single-threaded synchronous blocking iteration.
* Option B: Re-architect the application into a concurrent multi-threaded framework.



&#x20;*Rationale (Why Option B?)*



Option A suffers from severe CPU idle periods because the single thread blocks indefinitely waiting for individual port timeouts or handshakes. Option B leverages OS thread scheduling to overlap network latency across multiple ports, effectively minimizing I/O blocking bottlenecks and expanding scanning throughput.



*Design Trade-offs \& Sacrifices*

* Complexity \& Data Integrity: Moving away from deterministic linear execution introduced risks of data races on shared memory resources (`open\_ports` vector). This mandated synchronization primitives (`mutex`), introducing a secondary threat of lock contention.
* Protocol Footprints (Unchanged Constraint): As the application still relies on standard OS socket streams (`SOCK\_STREAM`), it remains bound to full TCP three-way handshakes, leaving obvious intrusion detection logs on target hosts.



