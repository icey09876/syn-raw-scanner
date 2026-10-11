# Development Log

A raw, unfiltered technical log of the low-level bugs, flawed initial assumptions and failed optimisation attempts encountered during development, and what each one taught.

## 2026-05-07: Concurrency: lock contention from mutex overuse

**1. The problem**

- At first, I found that multithreading caused a **data race**, so I used a `mutex` to protect the shared resources. However, this fix made the program **even slower than the single-threaded version**.

**2. Why (root cause)**

- I asked AI how to debug this performance drop. AI pointed out that it was caused by **lock contention**.
- The memory operation (`open_ports.push_back`) and the I/O operation (`cout`) have vastly different performance profiles. Putting them together inside the same lock expanded the critical section, causing heavy lock contention.

**3. How I solved it**

- Finally, I separated the locks by implementing **two distinct mutexes**: one dedicated to the fast memory operation (`open_ports.push_back`) and another separate one for the slow I/O operation (`cout`).
- This way, when a thread finishes its fast memory write, it can immediately release the vector lock, allowing other threads to proceed without being blocked by the slow console printing.

## 2026-10-11: Concurrency: more sender threads made the scanner miss open ports

**1. The problem**

- This was found during a code review with an AI assistant (Claude). The scanner was tested on the loopback interface (`127.0.0.1`) with five listening ports, scanning ports 1–10000 three times for each setting:

  | Sender threads (`-t`) | Open ports found (out of 5) |
  |---|---|
  | 1 | 5, 5, 5 |
  | 4 (the default) | 4, 1, 1 |
  | 16 | 0, 3, 0 |

- More threads were supposed to make the scan faster. Instead they made it silently wrong.

**2. Why (root cause)**

- Every probed port sends a reply: a SYN-ACK if it is open, a RST if it is closed. All of these replies wait in the raw socket's receive buffer until the receiver thread reads them, and the default buffer is only about 200 KB. With several threads sending at full speed, replies arrived faster than the single receiver thread could read them. Once the buffer was full, the kernel dropped new packets without any error, including the SYN-ACKs from open ports.
- The bug was introduced by the "optimize scanning performance" commit (`284c2b8`), which removed the `usleep(500)` between probes. That delay had been working as an accidental rate limit: with it restored, four threads found all five ports again, but the scan took about 2 seconds instead of about 0.5.
- Timing the send phase showed the threads barely helped anyway. Sending 10,000 probes took about 57 ms with one thread and about 20 ms with four, while the whole scan took about 550 ms, mostly the fixed 500 ms wait for late replies. In a SYN scan `sendto()` returns immediately without waiting for a handshake, so sending was never the bottleneck. The reason for using threads in the earlier `connect()` scanner (overlapping blocking waits) no longer applied.

**3. How it was fixed**

- The receive buffer is now raised to 32 MB with `SO_RCVBUFFORCE`, falling back to `SO_RCVBUF` when the program lacks the privilege. 8 MB was enough for ports 1–10000 but still lost replies on a full 1–65535 scan with four or more threads.
- After the change, every listening port was found in every run, with 1, 4, 16 and 64 threads, for both ports 1–10000 and 1–65535.
- Lesson: an "optimisation" should be checked against correctness as well as speed. Removing the delay made the timer look better but quietly broke the results, and only a repeatable test with known open ports showed it.
