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

##  Architecture
- **Ingress Hook:** Rewrites Dest Port 80 -> 8080 (DNAT).
- **Egress Hook:** Rewrites Src Port 8080 -> 80 (SNAT).
- **Checksum Logic:** Incremental $O(1)$ updates via `bpf_l4_csum_replace`.