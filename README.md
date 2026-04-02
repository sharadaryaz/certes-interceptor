# certes-interceptor

## The Mission: 

Transparently hijack any TCP traffic hitting Port 80 and shove it into Port 8080 using the kernel's own "Internal Firewalls" (eBPF).

## The Tech: 
* Rust (because we like memory safety and hage setfaults).

* Aya (Pure Rust eBPF, no C-strings for now).

* TC (Traffic Control) hooks (XDP is fast, but TC is smarter for local delivery, or maybe that is what I just learned).

##  The "War Log" (Day 1)

### Hour 0-3: The Mac Linker War
* **The Hurdle:** Attempted development on Apple Silicon Mac targeting Linux. (Just got a new Mac, did not want to go through the Virtual Machine pain on the 1st day)
* **The Pain:** Encountered the "5-register limit" in the BPF VM. The Mac LLVM linker kept trying to pull in heavy Rust `core::fmt` logic, which BPF can't handle.
* **Decision:** Pivoted to a native Ubuntu VM to ensure toolchain stability.

### Hour 4: The Shared Folder Curse
* **The Hurdle:** Permission Denied (OS Error 13) when building on VirtualBox Shared Folders (`vboxsf`).
* **The Decision:** `vboxsf` doesn't support POSIX locking required by Cargo. Moved the project to the VM's native filesystem.
* **Result:** Permission issues vanished.

### Hour 5: Native Liberation
* **Goal:** Rebuild from scratch on native Linux.
* **Success:** Environment is now 100% stable. Building natively on Ubuntu 24.04.
* **Lose:** Lost all commits from the Mac. Restarting the logs here.

### Hour 6: The "In-Progress" Ingress
* **The Goal:** Get the 80 -> 8080 redirection logic into the kernel.
* **The Implementation:** - Manually parsed Ethernet/IP/TCP headers using pointer arithmetic.
    - Used `bpf_l4_csum_replace` to fix the TCP checksum after the port rewrite.
* **The Status:** **Functional Success.** The code compiles natively (albeit a bunch of warnings; to be fixed in next commit hopefully) and the logic looks sound.

### Hour 12: Closing the Loop (Day 1 Final)
* **The Logic:** Completed the full NAT cycle. The interceptor now handles both the Ingress redirection (80 -> 8080) and the Egress return trip (8080 -> 80), ensuring seamless TCP handshakes.
* **The Toolchain:** Resolved the "Identity Crisis" between Kernel (`no_std`) and Host (`std`) modes. The codebase now supports seamless cross-compilation to BPF while maintaining host-side testability.
* **The Safety:** Upgraded to Rust 2024 safety standards. All `unsafe` operations are now explicitly scoped, and pointer arithmetic is verified through unit tests that simulate packet boundary conditions.
* **Status:** **Day 1 MVP Complete.** Bidirectional redirection is functional, verified, and warning-free.

## Day 2: The Orchestration Layer

### Hour 14: Hardening the User-Space Loader
* **The Goal:** Build a orchestrator to manage the kernel-to-user-space lifecycle.
* **The Implementation:**
    * **Dual TC Attachment:** Simultaneously loaded and attached both `certes_ingress` and `certes_egress` to create a complete, bidirectional NAT loop.
    * **Networking Qdisc Management:** Automated the initialization of the **`clsact`** queuing discipline on the target interface, ensuring the environment is prepared for eBPF attachment.
    * **Graceful Lifecycle:** Implemented `tokio` signal handling to ensure hooks are cleanly detached from the interface upon terminal exit (Ctrl-C).
    * **Operational Bridge:** Integrated `aya-log` to pipe kernel-level visibility directly into the user-space console.
* **The Result:** Verified full-stack 80 <-> 8080 redirection on the loopback interface with a single command. **Day 2 Infrastructure: Online.**

### Hour 22: Redirection Stability & Trace Logging
* **The Goal:** Deliver a redirection engine that meets the "metadata logging" requirement.
* **The Implementation:**
    * **Mapless Architecture:** Transitioned to `bpf_printk` for metadata logging. By eliminating BPF maps, we resolved the `os error 9` relocation conflicts caused by aya logs
    * **Kernel-Level Auditing:** Metadata is now streamed directly to the kernel's debug buffer, providing a high-performance audit trail with zero user-space overhead.
* **Post-Mortem:** Failed Logging Approaches. 
 We attempted metadata aggregation via BPF HashMaps and streaming via aya-log, but both triggered os error 9 (Bad file descriptor) due to toolchain drift and map relocation conflicts. The verifier also rejected post-helper pointer usage, forcing a pivot to mapless bpf_printk to ensure immediate stability and bypass relocation failures.
* **The Result:** Full bidirectional 80 <-> 8080 redirection is operational. 
* **Observation:** Logs can be viewed in real-time via: `sudo cat /sys/kernel/debug/tracing/trace_pipe`.

## Day 3: Service Hardening & Persistence

### Hour 24: Systemd Integration (Always-On)
* **The Goal:** Ensure the interceptor is always on and survives system reboots.
* **The Implementation:**
    * **Service Unit:** Created a **systemd** service to manage the lifecycle of the eBPF loader.
    * **Automation:** Developed a **Makefile** to unify the cross-compilation and installation process.
* **The Result:** The module is now a managed system utility. Persistence is 100% achieved.

##  Architecture
- **Ingress Hook:** Rewrites Dest Port 80 -> 8080 (DNAT).
- **Egress Hook:** Rewrites Src Port 8080 -> 80 (SNAT).
- **Checksum Logic:** Incremental $O(1)$ updates via `bpf_l4_csum_replace`.