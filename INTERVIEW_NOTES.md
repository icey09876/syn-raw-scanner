\# Guide: This document serves as a raw, unfiltered technical log of the low-level bugs, flawed initial assumptions, and failed optimization attempts encountered during development. Its purpose is to preserve technical insights for future interview preparation and post-mortem reviews.





\## Log: 2026-05-07 - Concurrency: Lock Contention in Mutex Overuse



\## 📌 Log: 2026-05-07 - Concurrency: Lock Contention in Mutex Overuse



&#x20;*1. The Problem*

* At first, I found that multithreading caused a \*\*data race\*\*, so I used a `mutex` to protect the shared resources. However, this fix made the program \*\*even slower than the single-threaded version\*\*.



&#x20;*2. Why (Root Cause)*

* &#x20;I asked AI how to debug this performance drop. AI pointed out that it was caused by \*\*lock contention\*\*.
* &#x20;The memory operation (`open\\\\\\\_ports.push\\\\\\\_back`) and the I/O operation (`cout`) have vastly different performance profiles. Putting them together inside the same lock expanded the critical section, causing heavy lock contention.



&#x20;*3. How I Solved It*

* &#x20;Finally, I separated the locks by implementing \*\*two distinct mutexes\*\*: one dedicated to the fast memory operation (`open\\\\\\\_ports.push\\\\\\\_back`) and another separate one for the slow I/O operation (`cout`).
* &#x20;This way, when a thread finishes its fast memory write, it can immediately release the vector lock, allowing other threads to proceed without being blocked by the slow console printing.



