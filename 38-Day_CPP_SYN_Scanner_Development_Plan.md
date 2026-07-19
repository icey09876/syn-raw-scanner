# 38-Day Advanced C++ SYN Scanner Rolling Development Plan

## Phase 1: Network Fundamentals & C++ Memory Basics (Day 1 – Day 10)
**Core objective:** Build a protocol-level understanding of networking while filling in the C++ fundamentals required for raw socket programming later on.

**Daily breakdown:**
- **Day 1** — Introduction to Wireshark packet capture. Observe the TCP three-way handshake; identify SYN, SYN-ACK, and ACK packets.
- **Day 2** — Study the half-open scan process. Understand why SYN scanning is stealthier than a full Connect scan; identify the 0x02 and 0x12 flag bytes.
- **Day 3** — Structs and memory layout. Understand padding (memory alignment); experiment with `#pragma pack(push,1)`.
- **Day 4** — Advanced Wireshark filters. Practice filtering by specific IP, port, and TCP flags.
- **Day 5** — Byte order fundamentals. Understand Little Endian vs. Big Endian; experiment with `htons()` and `htonl()`.
- **Day 6** — Pointer basics. Understand `&`, `*`, pointer variables, and dereferencing; write simple pointer demos.
- **Day 7** — Combining structs and pointers. Practice struct addresses, struct pointers, and the `->` operator.
- **Day 8** — Memory manipulation functions. Learn `memcpy`, `memset`, `sizeof`; complete a byte-copying exercise.
- **Day 9** — Type casting. Learn `reinterpret_cast` to interpret raw byte arrays directly as structs.
- **Day 10** — Integrated exercise: construct a 20-byte IP header struct, print it, and visually inspect the actual memory layout of each field.

## Phase 2: Connect Scanner & Concurrency Fundamentals (Day 11 – Day 16)
**Core objective:** Use a real scanner to motivate threading and locking, and confront concurrency pain points firsthand.

**Daily breakdown:**
- **Day 11** — Winsock initialization. Learn `WSAStartup()` and `socket()`; implement connecting to a single port on a single IP.
- **Day 12** — Single-threaded Connect scanner. Loop through ports 1–1024 and observe the severe performance bottleneck.
- **Day 13** — Recording scan results. Use `std::vector` to store open ports, setting up the data race that multithreading will later expose.
- **Day 14** — Introduce `std::thread`. Run multiple threads scanning concurrently; observe firsthand how console output gets garbled/interleaved.
- **Day 15** — Learn Mutex. Use `std::mutex` and `std::lock_guard` to protect standard output and fix the console ordering issue.
- **Day 16** — Protect the shared vector. Lock the open-port list during writes to produce a stable multithreaded Connect scanner; use Wireshark to observe the complete TCP three-way handshake traffic.

## Phase 3: Raw Sockets & Hand-Crafted Packets (Day 17 – Day 23)
**Core objective:** Bypass the OS network stack and manually assemble a standard 40-byte TCP packet in memory, byte by byte.

**Daily breakdown:**
- **Day 17** — Raw socket theory. Understand the fundamental difference between kernel-level automatic packet construction and manual, user-space packet construction.
- **Day 18** — Define the IP header struct. Design a 20-byte IP header struct against the RFC specification.
- **Day 19** — Define the TCP header struct. Design a 20-byte TCP header struct.
- **Day 20** — Build the 40-byte buffer. Create a `char buf[40]` and use `memcpy` to precisely splice the IP and TCP headers together.
- **Day 21** — Internet checksum theory. Hand-write the checksum calculation function; understand the "one's complement sum" math behind it.
- **Day 22** — Conquer the TCP pseudo-header. Introduce the 12-byte pseudo-header into the code and combine it with the previous day's checksum function to correctly compute the TCP checksum — the hardest part of the process.
- **Day 23** — Raw TCP SYN packet-sending experiment. Run with administrator privileges, create a `SOCK_RAW` socket, call `sendto` to send a custom SYN packet, and verify with Wireshark that the NIC allows it through.

## Phase 4: Closing the Send/Receive Loop & Timeout Control (Day 24 – Day 29)
**Core objective:** Avoid a disconnect between sending and receiving logic — implement a working, single-threaded "send and receive" loop.

**Daily breakdown:**
- **Day 24** — `recvfrom` basics. Write code to receive returned packets and print the raw hex bytes received.
- **Day 25** — Parse the returned TCP header. Use pointer casting to identify whether the response flags indicate SYN-ACK or RST, and determine port status accordingly. (Bitwise operators: `& | ~ << >>`)
- **Day 26** — Timeout mechanism. Learn `setsockopt` to adjust `SO_RCVTIMEO`, preventing `recvfrom` from hanging indefinitely when a port is closed.
- **Day 27** — Single-threaded send/receive loop. Chain sending and receiving together: send a SYN → immediately receive the response → output port status.
- **Day 28** — Joint verification with Wireshark. Confirm that every byte sent by the code and every byte received by the NIC is logically correct.
- **Day 29** — Code refactoring. Split loose code into independent send, receive, and parse modules/functions in preparation for dual-threading.

## Phase 5: Asynchronous Receiving & I/O Multiplexing (Day 30 – Day 34)
**Core objective:** Solve the CPU busy-waiting and high-concurrency packet-loss problems inherent to a dual-thread architecture.

**Daily breakdown:**
- **Day 30** — Establish dual-thread architecture. Fully split the code into an independent Send Thread and Recv Thread.
- **Day 31** — Synchronize the shared result set. Use the mutex learned on Day 15 to protect the open-port vector shared and accessed by both threads.
- **Day 32** — `select` theory. Understand the `fd_set` collection and `timeval` structure; grasp the kernel notification mechanism.
- **Day 33** — Introduce `select`. Use `select()` to guard `recvfrom`, so the code only wakes up when a packet is actually available and stays suspended otherwise — solving the problem of CPU usage spiking to 100%.
- **Day 34** — Large-scale port scan experiment. Scan several thousand ports locally to verify the scanner's speed and stability under high concurrency.

## Phase 6: Performance Optimization & Tooling (Day 35 – Day 38)
**Core objective:** Elevate the project's academic weight and shape it into a solid piece of evidence for the university application (Personal Statement) and interviews.

**Daily breakdown:**
- **Day 35** — Thread pool concept. Understand the Worker and Task Queue model; cap the number of concurrent threads to avoid overwhelming the system with unrestrained thread creation.
- **Day 36** — Command-line argument parsing. Support `main(int argc, char* argv[])`, adding dynamic flags such as `-h` (host), `-p` (port), and `-t` (threads).
- **Day 37** — Performance testing and tuning. Measure and optimize scan speed, CPU usage, and response time; record a terminal video of scanning tens of thousands of ports within seconds.
- **Day 38** — Project write-up and documentation. Consolidate key technical themes — protocol analysis, raw socket implementation, multithreaded synchronization, the select mechanism — into polished material for the Personal Statement and interview.

---
*End of plan*
