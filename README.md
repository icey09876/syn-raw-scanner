# syn-raw-scanner

A TCP SYN ("half-open") port scanner for Linux, written in C++17. It builds every IPv4 and TCP header by hand, sends the packets through a raw socket and parses the replies itself, so no full TCP connection is ever opened.

The project was built over about 38 days as a learning exercise. It started as an ordinary `connect()` scanner and grew step by step: hand-built packet headers, checksums, a separate receiver thread, `select()`-based I/O, a worker thread pool and command-line options. The commit history follows that path.

> **Only scan hosts you own or have explicit permission to scan.** Scanning other people's networks may be illegal where you live.

## How a SYN scan works

For each port, the scanner sends one TCP packet with only the SYN flag set, which is the first step of the TCP three-way handshake. The reply says what state the port is in:

| Reply from the target | Meaning |
|---|---|
| SYN-ACK | **Open**: a service is listening |
| RST | Closed |
| No reply | Filtered (for example by a firewall), or a packet was lost |

When a SYN-ACK arrives, the scanning machine's kernel has no socket bound to the source port, so it automatically answers with a RST. The handshake is never completed, which is why this is called a half-open scan. Unlike a `connect()` scan, the service on the target never receives a connection.

This scanner currently reports **open** ports only (see [Limitations](#limitations)).

## Building packets by hand

`Protocal.h` defines the 20-byte IPv4 header, the 20-byte TCP header and the 12-byte TCP pseudo-header as structs. `#pragma pack(push, 1)` stops the compiler from inserting padding, so each struct matches the on-wire layout byte for byte. Bit-fields hold the 4-bit fields (IP version, IHL, TCP data offset) and the individual TCP flags.

`BuildSynPacket()` in `main.cpp` does the following:

1. Fills in the IP header (version 4, IHL 5, TTL 64, protocol TCP) and the TCP header (SYN flag, data offset 5, window 1024). Multi-byte fields are converted to network byte order with `htons()` / `htonl()`.
2. Copies both headers into one 40-byte buffer.
3. Computes the TCP checksum over the pseudo-header plus the TCP header, and the IP header checksum. Both use the Internet checksum: the ones' complement of the ones' complement sum of 16-bit words (RFC 1071).
4. Writes the two checksums back into the buffer at byte offsets 36 and 10.

The socket is created with `socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` and the `IP_HDRINCL` option, which tells the kernel that the buffer already contains an IP header. (Linux recomputes the IP header checksum for raw sockets anyway, see `man 7 raw`. The TCP checksum is entirely the program's responsibility.)

## Architecture

```
                 port queue (std::queue + mutex + condition_variable)
main thread ──▶  [ 1 | 2 | 3 | ... | N ]
                    │         │         │
                    ▼         ▼         ▼
                sender 1  sender 2 … sender T          (-t threads)
                    └─────────┼─────────┘
                              ▼ sendto()
                         raw socket ──────────▶ target
                              ▲ recvfrom()
                              │
                      receiver thread  ◀── select() with a 1 s timeout
                              │ SYN-ACK with matching port and ACK number?
                              ▼
                 open_ports (vector + mutex) ──▶ sort, de-duplicate, print
```

- **Sender threads** form a fixed-size worker pool. Each one waits on a condition variable, takes the next port from the shared queue, builds a SYN packet and sends it. A worker exits once the queue is empty and the main thread has marked every port as added.
- **The receiver thread** starts before the senders, so no early reply is missed. It waits with `select()` and a 1-second timeout instead of a blocking `recvfrom()`. That way it never blocks forever when no packets arrive, and it regularly checks the `std::atomic<bool>` stop flag.
- **Matching replies:** a packet counts as an answer to one of the probes when it has both SYN and ACK set, its destination port is the scanner's source port (12345), and its acknowledgement number is the probe's sequence number + 1.
- **Shutdown:** after all senders finish, the main thread waits 500 ms for late replies and then stops the receiver. Finally it sorts and de-duplicates the results, because a target may retransmit its SYN-ACK.

Design decisions and their trade-offs are recorded in [DECISION.md](DECISION.md). Bugs and wrong assumptions met along the way are logged in [INTERVIEW_NOTES.md](INTERVIEW_NOTES.md).

## Requirements

- Linux. The code uses POSIX socket headers; Windows and macOS are not supported.
- A C++17 compiler (g++ or clang++)
- CMake 4.1 or newer, or build with g++ directly (see below)
- Root privileges or the `CAP_NET_RAW` capability, because raw sockets are privileged

## Build

```bash
cmake -S . -B build
cmake --build build
# the binary is build/main
```

Without CMake:

```bash
g++ -std=c++17 -O2 -pthread main.cpp -o main
```

## Usage

```bash
sudo ./main -s <source-ip> -h <target-ip> -p <start>-<end> -t <threads>
```

| Option | Meaning | Default |
|---|---|---|
| `-s` | Source IP written into each packet: the address of your own network interface | `172.25.176.246` |
| `-h` | Target IP address | `192.168.31.1` |
| `-p` | Port range, e.g. `1-1024`. A single port such as `80` also works. | `1-10000` |
| `-t` | Number of sender threads | `4` |

The defaults match the author's test setup, so always pass `-s` and `-h` on another machine. To find the right source address for a target, run:

```bash
ip route get 192.168.1.1    # use the address shown after "src"
```

### Example

Start two local services, then scan the loopback interface:

```bash
python3 -m http.server 8000 --bind 127.0.0.1 &
python3 -m http.server 8080 --bind 127.0.0.1 &
sudo ./main -s 127.0.0.1 -h 127.0.0.1 -p 3000-9000 -t 1
```

```
open port:8000
open port:8080
elapsed: 541 ms
```

Most of the elapsed time is the fixed 500 ms wait for late replies.

### Checking the packets in Wireshark

Capture on the interface you scan from and apply the display filter `tcp.port == 12345`. For an open port there should be three packets: the scanner's SYN, the target's SYN-ACK, and the RST sent by the scanning machine's kernel. To have Wireshark verify the TCP checksum, enable *Validate the TCP checksum if possible* under Preferences → Protocols → TCP.

## Project structure

| File | Contents |
|---|---|
| `main.cpp` | Checksum, packet builder, reply parser, sender and receiver threads, command-line parsing |
| `Protocal.h` | Packed IPv4, TCP and pseudo-header structs |
| `CMakeLists.txt` | Build configuration |
| `DECISION.md` | Architecture decisions and trade-offs |
| `INTERVIEW_NOTES.md` | Log of bugs, wrong assumptions and how they were fixed |
| `38-Day_CPP_SYN_Scanner_Development_Plan.md` | The day-by-day development plan |

## Limitations

- Only **open** ports are reported. Closed ports (RST) and filtered ports (no reply) are not told apart yet.
- There is no retransmission and no rate limiting. If a probe or its reply is dropped, either on the network or because the receiver cannot keep up, the port is missed. `-t 1` gives the most reliable results.
- Every probe uses the same source port (12345), sequence number (1000) and IP ID, which makes the scan easy to fingerprint. Replies are not checked against the target's IP address.
- IPv4 only, one target per run. The bit-field layout in `Protocal.h` assumes a little-endian CPU (x86 and most ARM systems).
- Command-line input is barely validated: an invalid port range or IP address can crash the program or give wrong results.

## Possible next steps

- Classify ports as open, closed or filtered using RST replies and timeouts
- Retransmit unanswered probes and add a configurable send rate
- Randomise the source port and sequence number per scan, and check each reply's source IP
- Detect the source IP automatically instead of requiring `-s`
- Validate command-line input and print a proper usage message

## References

- [RFC 791](https://www.rfc-editor.org/rfc/rfc791): Internet Protocol
- [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293): Transmission Control Protocol (replaces RFC 793)
- [RFC 1071](https://www.rfc-editor.org/rfc/rfc1071): Computing the Internet Checksum
- `man 7 raw`, `man 7 ip`, `man 2 select`
- [Nmap Reference Guide: TCP SYN scan](https://nmap.org/book/synscan.html)
