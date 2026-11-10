# In-Memory PE Runtime & Integrity Protection Engine
### Defensive Anti-Tamper & Zero-Disk Execution Pipeline
**Language:** Modern C++ (C++20) / Win32 / x86 & x64 Assembly  
**Discipline:** Systems Software Engineering, Windows Internals, Anti-Tamper Hardening

---

> [!NOTE]
> **Production Status & Intellectual Property Notice:**  
> This repository is an **architectural case study and systems specification** derived from a proprietary, active production system (serving 8,000+ monthly user sessions across global edge infrastructure). In accordance with commercial confidentiality agreements and anti-tamper security practices, live memory offsets, internal game mappings, private Cloudflare routing tokens, and core binaries are strictly omitted.
## Executive Summary

When distributing client performance software in competitive environments, on-disk libraries (`.dll`) present severe security hazards: arbitrary code injection, binary repackaging with malware, and DLL search-order hijacking. Standard OS loaders (`LoadLibrary`) exacerbate this by exposing the module directly in the process environment block (`PEB`).

This project implements a **zero-disk, in-memory execution pipeline** designed to safeguard proprietary software integrity:
- **Zero Disk Artifacts:** Payloads are fetched via ephemeral edge pipelines and mapped directly into remote virtual memory without touching the local filesystem.
- **Defensive Anti-Tamper:** Employs Mixed Boolean-Arithmetic (MBA), Anti-Symbolic Execution (ASE), and Vectored Exception Handling (VEH) to resist automated reverse engineering and decompilation.
- **Fail-Closed Architecture:** Security parameters are mathematically bound to downstream runtime execution keys, neutralizing classical single-jump assembly bypasses.

> 📄 **Looking for the complete technical breakdown?**  
> Read the full 10-minute engineering specification: **[Architecture Deep Dive & Systems Whitepaper](docs/architecture-deep-dive.md)**.

---

## High-Level System Architecture

```mermaid
flowchart TD
    subgraph CloudflareEdge["1. Edge Distribution (Sub-500µs CPU)"]
        CF[Cloudflare Worker Node] -->|Handshake & Auth| AUTH[Version Verifier]
        AUTH -->|Zero Edge Caching| STREAM[Stream Payload Buffer]
    end

    subgraph NativeLoader["2. Loader Orchestrator (Modern C++20 / Win32)"]
        WV[WebView2 UI Bridge] <-->|IPC| ORCH[Loader Core Orchestrator]
        STREAM -->|Encrypted HTTPS Fetch| ORCH
        ORCH -->|Locate Target Process| MMAP[Defensive Manual Mapper]
    end

    subgraph TargetVM["3. Protected Target VM (JVM / Game Process)"]
        MMAP -->|VirtualAllocEx + Write Sections| TGT_MEM[(Remote Virtual Memory)]
        MMAP -->|NtCreateThreadEx 0x4 Stealth| BOOT[Bootstrap Shellcode]
        
        BOOT -->|Recalculate Offsets| RELOC[Base Relocations: DIR64 / HIGHLOW]
        BOOT -->|Iterate INT & Resolve| IAT[Manual Import Address Table]
        BOOT -->|Register x64 Unwind| SEH[RtlAddFunctionTable]
        BOOT -->|Execute EntryPoint| ENGINE[Core Hardened Engine]
        
        ENGINE -->|MBA & VEH Guards| SEC[Anti-Debug / Anti-Tamper Core]
        ENGINE -->|Thread Safe Hooking| JVMTI[JVMTI Runtime Alignment]
    end
```

---

## Core Engineering Pillars

| Subsystem | Technical Implementation | Purpose / Threat Mitigated |
| :--- | :--- | :--- |
| **In-Memory PE Mapping** | Custom shellcode parsing `IMAGE_NT_HEADERS`, virtual section alignment, and ephemeral memory scrubbing. | Eliminates disk footprint, `%TEMP%` forensics, and standard `PEB` module table detection. |
| **Base Relocations** | Dynamic delta calculation traversing `IMAGE_BASE_RELOCATION` blocks for both `DIR64` and `HIGHLOW`. | Allows seamless execution at arbitrary virtual base addresses without OS relocation helpers. |
| **Manual IAT Resolution** | Iterates `OriginalFirstThunk` (INT), resolves module exports via hashing, and dynamically populates `FirstThunk`. | Obfuscates external API dependencies and eliminates cleartext import table signatures. |
| **Anti-Symbolic Hardening** | Mixed Boolean-Arithmetic (`MBA_XOR`, `MBA_ADD`) and Vectored Exception Handling (`VEH_GUARD`). | Defeats automated SMT/SAT solvers (Triton/Angr/Z3) and static linear control-flow decompilers. |
| **JVMTI Interoperability** | Asynchronous class-cache anchoring decoupled from the JVM `ClassLoader` dictionary mutex. | Solves circular AB-BA acquisition deadlocks during high-load render loop execution. |

---

## Production Scale & Telemetry Benchmarks

Continuously operated in global production via Cloudflare Workers without operational degradation:

- **CPU Compute Duration:** `~540 µs` average execution time per handshake.
- **Total Request Latency:** `~800 µs` (sub-millisecond edge response).
- **Monthly Invocations:** `8,000+` active requests across 30+ global edge locations.
- **Uptime & Reliability:** `0.00%` operational error rate over 4+ months of continuous deployment.

---

## Documentation Index

- **[docs/architecture-deep-dive.md](docs/architecture-deep-dive.md):** Complete whitepaper covering PE parsing math, relocation algorithms, JVM deadlock war story, trade-off matrix, and V2 memory protection roadmap.

---

## Ethical Disclosure

This architecture was developed exclusively for **legitimate client-side performance optimization** and **proprietary IP protection against malicious payload hijacking**. Offsets and private production keys have been fully sanitized.