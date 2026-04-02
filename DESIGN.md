# Design & Architecture: certes-interceptor

This document outlines the technical decisions, challenges, and architectural trade-offs made during the development of the **certes-interceptor**, a eBPF NAT service built for the Certes Networks technical assessment.

---

## 1. Core Philosophy

### Why eBPF & Rust?
To achieve the lowest possible latency, packet redirection was implemented directly in the kernel using **TC (Traffic Control) SchedClassifier** hooks. This approach bypasses the overhead of the user-space networking stack and ensures the redirection is transparent to the applications running on ports 80 and 8080.

**Rust** was selected over C to leverage its strict memory safety guarantees, which are vital when injecting code into a live kernel. The **Aya** framework was chosen specifically to allow a unified, pure-Rust toolchain. Unlike traditional BCC or C-based eBPF development, Aya compiles directly to BPF bytecode and requires no LLVM or Clang runtimes on the target machine.

---

## 2. Architecture & Strategy

The project utilizes a three-crate workspace scaffolded via the `aya-template`:
* **`certes-interceptor-ebpf`**: Contains the kernel-space bytecode for packet surgery.
* **`certes-interceptor`**: An asynchronous `tokio` loader that manages the eBPF lifecycle.
* **`certes-interceptor-common`**: Shared data structures ensuring type-safe communication between kernel and user-space.

### The NAT Loop
The interceptor functions as a bidirectional NAT loop. An **Ingress Hook** intercepts traffic destined for Port 80, rewrites it to 8080, and updates the L4 checksum. Simultaneously, an **Egress Hook** intercepts response traffic from Port 8080 and reverts it to Port 80 to maintain connection persistence for the client.

---

## 3. Development Challenges

The development process involved navigating the rigorous constraints of the eBPF verifier. A primary hurdle was the **verifier’s register invalidation rules**; calling BPF helper functions (like map lookups) causes the verifier to "forget" the safety bounds of previously validated packet pointers (or at least this is what I assume was happening). This was solved by rearchitecting the logic to perform all memory writes immediately after bounds checks.

Additionally, a **`Bad file descriptor (os error 9)`** failure during program loading was diagnosed as a **Map Relocation mismatch** caused by version drift between the compiler and the loader. This was resolved by pinning all dependencies to a specific Git revision (`39929775`) to ensure binary parity. Finally, the **`'static` lifetime constraints** of the `tokio` runtime were managed by pivoting to a `tokio::select!` loop, ensuring all data references remained local and memory-safe.

---

## 4. Engineering Trade-offs

### The "Trace Pipe" Pivot
While the initial plan included real-time statistics via BPF HashMaps, toolchain drift on the target system made map relocation unstable. A decision was made to prioritize a working NAT loop over complex stats. 

> **The Decision:** The implementation was shifted to a mapless architecture using **`bpf_printk`**. By eliminating BPF maps, relocation failures were bypassed entirely, ensuring the core redirection logic was rock-solid while still fulfilling the requirement to log packet metadata via the kernel’s trace buffer.

---

## 5. Future Roadmap

With additional development time, the following enhancements would be prioritized:
* **Dynamic Configuration**: Replacing hardcoded interface names with a YAML-based configuration loader.
* **Map Infrastructure Recovery**: Resolving BTF (BPF Type Format) generation issues to restore structured user-space dashboards.
* **Performance Profiling**: Using `bpftrace` to quantify the exact nanosecond latency added per packet.

---
[← Back to README](./README.md)