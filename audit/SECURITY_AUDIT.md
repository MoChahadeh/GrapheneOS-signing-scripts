# Security Audit — GrapheneOS `hardened_malloc`

**A claims-driven, defensive source audit of the GrapheneOS hardened memory allocator**

| | |
|---|---|
| **Target** | GrapheneOS `hardened_malloc` |
| **Upstream** | https://github.com/GrapheneOS/hardened_malloc |
| **Commit audited** | `9e88c14305440c45551789c284c1de08ec08e451` (`9e88c14`, *"add native_bridge_supported for Cuttlefish build"*) |
| **Configurations reviewed** | `config/default.mk` (full hardening) and `config/light.mk` (performance-oriented) |
| **Audit type** | Static source review, authorized / defensive (security research & education) |
| **Audit date** | 2026-06-16 |
| **Methodology** | Claims-driven subsystem decomposition; six independent specialist reviewers; lead synthesis with independent code verification |
| **Source LoC reviewed** | ~3,400 lines of first-party C/C++ (`h_malloc.c`, `random.c`, `chacha.c`, `memory.c`, `pages.c`, `new.cc`, headers) |

---

## 1. Executive Summary

`hardened_malloc` is GrapheneOS's security-focused replacement for the standard
Android/Bionic native allocator. On stock Android the native heap is served by
**Scudo** (and historically **jemalloc**); GrapheneOS replaces that with
`hardened_malloc`, integrated directly into Bionic as the system `malloc`. Because
it is a *from-scratch* allocator rather than a patch set, the security-relevant
"diff against AOSP" is effectively the entire codebase and, more importantly, the
**design**: fully out-of-line metadata, per-size-class isolated regions with
high-entropy random bases, pervasive guard pages, randomized/delayed free
(quarantines), slab canaries, zero-on-free, a ChaCha8-based CSPRNG, and ARM
Memory Tagging Extension (MTE) support.

This audit evaluated whether the **implementation faithfully delivers the
security properties the project claims** (as documented in its README "Security
properties", "Core design", "Randomness", and "Memory tagging" sections), and
searched for genuine weaknesses. The codebase was decomposed into six
security-critical subsystems, each reviewed in depth by a dedicated reviewer, with
the lead auditor independently verifying the highest-impact findings against the
source.

### Headline result

> **No memory-safety vulnerabilities were identified in any subsystem.** The
> allocator's core security claims hold — many fully, several with
> well-characterized caveats that the project itself already documents. The
> findings are dominated by **inherent design tradeoffs** (probabilistic
> mitigations, bounded quarantines) and a small number of **low-severity,
> defense-in-depth hardening suggestions**. This is the expected — and
> reassuring — outcome for a mature, heavily-reviewed, widely-deployed allocator.

### Severity breakdown

| Severity | Count | Notes |
|---|---:|---|
| **Critical** | 0 | — |
| **High** | 0 | — |
| **Medium** | 1 | `HARDEN-07` — security *delta of the `light` config* vs `default`; not a defect |
| **Low–Medium** | 2 | `HARDEN-01` (per-slab canary), `HARDEN-05` (bounded quarantine) — accepted tradeoffs |
| **Low** | 17 | Defensive hardening suggestions and minor robustness/entropy observations |
| **Informational** | 30 | ~half are explicit *verified-correct strengths* (positives) |
| **Total** | **50** | Across 6 subsystems |

### What an integrator should take away

- The **design lives up to its reputation.** Out-of-line metadata, deterministic
  invalid-free / double-free detection, ASLR-friendly layout, and a correct
  ChaCha8 CSPRNG are all confirmed in code.
- The **mitigations are honest about being probabilistic.** Canaries *absorb*
  more than they *detect*; quarantines *delay* rather than *prevent* reuse. The
  documentation states this; the code matches the documentation.
- There is **no urgent action.** The handful of concrete code suggestions
  (§7) are low-priority fail-closed / future-proofing improvements, not fixes
  for exploitable bugs.
- **Configuration matters.** The `default` configuration is substantially
  stronger than `light` for temporal-safety (use-after-free / double-free)
  threat models. Deployments that care about UAF should ship `default`.

---

## 2. Scope & Methodology

### 2.1 In scope

The first-party allocator source at commit `9e88c14`:

| Area | Files |
|---|---|
| Core slab allocator | `h_malloc.c` (small-allocation paths, slab metadata, bitmaps, slot geometry, locking, fork safety) |
| Large allocations & region table | `h_malloc.c` (`allocate_large`/`deallocate_large`, `regions_*`, large quarantine) |
| Randomness / CSPRNG | `random.c`, `random.h`, `chacha.c`, `chacha.h` |
| Heap-hardening mitigations | `h_malloc.c` (canaries, zero-on-free, write-after-free, slab quarantine) |
| Memory primitives & isolation | `memory.c`, `memory.h`, `pages.c`, `pages.h`, `h_malloc.c` (layout/init/MPK/fork) |
| MTE, C++ allocator, API surface | `arm_mte.h`, `memtag.h`, `new.cc`, `include/h_malloc.h`, integer-overflow & alignment handling |
| Build configuration | `Makefile`, `config/default.mk`, `config/light.mk` |

### 2.2 Out of scope

- The **Bionic/GrapheneOS integration glue** (lives in `platform_bionic`, not this
  repository), including the seccomp-bpf syscall filter and the libc wiring.
- **Third-party vendored code** (`third_party/libdivide.h`) was treated as a
  trusted, well-known dependency and reviewed only at its call sites.
- **Dynamic analysis** (fuzzing, sanitizer runs, exploitation PoCs) and
  **on-hardware MTE execution** were not performed; this is a source-level audit.
  The in-tree functional/security tests (`test/`, `androidtest/`) were read as
  corroborating evidence but not executed.

### 2.3 Methodology

This was a **claims-driven audit**: rather than reading the code in a vacuum, each
reviewer was given the specific security properties the project advertises for
their subsystem and tasked with verifying — against the actual source — whether
each property holds, holds with caveats, or fails.

1. **Decomposition.** The allocator was split into the six subsystems above,
   chosen to minimize overlap while guaranteeing full coverage of the
   security-relevant code.
2. **Independent specialist review.** Six reviewers worked in parallel, each
   producing a structured findings report (full reports in
   [`findings/`](./findings/)). Reviewers were explicitly instructed to be
   intellectually honest, to classify every finding by type, to cite exact
   `file:line` evidence, **not** to fabricate vulnerabilities or invent CVEs, and
   to document genuine strengths as well as weaknesses.
3. **Independent verification by the lead.** The highest-impact technical claims
   were re-checked directly against the source by the lead auditor, including:
   - the free-path **check ordering** in `deallocate_small`
     (`h_malloc.c:805-893`) — confirmed bounds → alignment → double-free →
     canary validation all precede any memory/metadata mutation;
   - the **per-slab canary** design (`set_slab_canary_value`/`set_canary`,
     `h_malloc.c:514-544`) — confirmed one value per slab, reused across slots;
   - the **`get_random_bytes` reseed-accounting** gap (`random.c:54-74`) —
     confirmed the bulk path returns before `reseed` is advanced.
4. **Synthesis.** Findings were consolidated, de-duplicated, severity-normalized,
   and mapped back to the advertised security claims (§6).

### 2.4 Severity & classification scheme

Each finding carries a **severity** and a **type**. The type is essential for an
honest reading of this audit: the large majority of findings are *not* defects.

**Severity**

- **Critical / High** — exploitable memory-safety or a broken core guarantee.
  *(none found)*
- **Medium** — a meaningful security weakness or a substantial reduction in a
  protection relative to the design intent.
- **Low** — minor weakness, robustness nit, or a defensive improvement with real
  but limited value.
- **Informational** — observations, design notes, and **verified-correct
  strengths** (positives).

**Type**

- **Bug** — a real implementation defect. *(none found)*
- **Design-limitation** — an inherent or explicitly-documented tradeoff of the
  chosen design (e.g. probabilistic canaries, fixed-size quarantine).
- **Defense-in-depth** — a hardening suggestion that would raise the bar but is
  not required for correctness.
- **Verified-correct / Strength** — a property checked and confirmed sound.

---

## 3. Background: `hardened_malloc` vs. the AOSP allocator

Stock AOSP serves native allocations from Scudo (a security-conscious but
performance-first allocator) or, on older releases, jemalloc. `hardened_malloc`
takes a deliberately different posture: it is **solely focused on hardening**,
accepts measurable performance and virtual-memory costs in exchange for security,
and is exclusively 64-bit so it can spend the abundant address space on isolation
and randomization. Its design lineage is OpenBSD `malloc` (re-implemented, not
forked) with size/type partitioning inspired by PartitionAlloc.

The security-relevant differences from a conventional allocator — and therefore
the substance of this audit — are:

- **Fully out-of-line metadata.** No inline chunk headers or free-list pointers
  live in user-accessible memory, eliminating the canonical heap-metadata
  corruption primitives.
- **Region isolation.** A multi-terabyte slab region is statically reserved and
  carved into per-arena, per-size-class sub-regions, each with a high-entropy
  random base and interspersed guard slabs.
- **Deterministic integrity checks.** Every free is validated (range, alignment,
  used-state, double-free, sized-deallocation) before any state changes.
- **Randomized & delayed reuse.** Slab and large-allocation quarantines (FIFO +
  random array) plus randomized slot selection frustrate UAF grooming.
- **Probabilistic absorbers/tripwires.** Slab canaries, zero-on-free, and a
  write-after-free zero-scan.
- **Hardware integration.** ARM MTE for probabilistic spatial and deterministic
  temporal safety; x86-64 Memory Protection Keys (MPK) for metadata sealing.

---

## 4. Architecture Overview

```
                       hardened_malloc address space (64-bit only)
   ┌───────────────────────────────────────────────────────────────────────┐
   │  Slab region  (≈ ARENA_SIZE × N_ARENA, default ≈ 12.25 TiB, PROT_NONE)  │
   │   ┌──────────── arena 0 ────────────┐        ┌──── arena N-1 ────┐       │
   │   │ size-class region 0  (rand base)│  ...   │  ...              │       │
   │   │  [slab][guard][slab][guard]...  │        │                   │       │
   │   │ size-class region 1  (rand base)│        │                   │       │
   │   └─────────────────────────────────┘        └───────────────────┘       │
   └───────────────────────────────────────────────────────────────────────┘
   ┌───────────────────────────────────────────────────────────────────────┐
   │  allocator_state  (out-of-line WRITABLE metadata)                       │
   │   guard │ slab_metadata arrays · region hash table · per-class CSPRNGs │
   │  (rand) │ · free/empty/partial/quarantine lists · locks       │ guard  │
   └───────────────────────────────────────────────────────────────────────┘
   ┌───────────────────────────────────────────────────────────────────────┐
   │  ro  (page, read-only after init): POINTERS into allocator_state + pkey │
   └───────────────────────────────────────────────────────────────────────┘

   Large allocations ( > max_slab_size_class ):  standalone mmap mappings,
   random guard region on both sides, tracked in the region hash table,
   PROT_NONE-quarantined on free.
```

**Small (slab) path.** A request is rounded to one of ~49 jemalloc-style size
classes (canary added first). The arena and size class are derived purely from a
pointer's address bits. Each slab is an array of fixed-size slots tracked by a
256-bit free bitmap plus a parallel quarantine bitmap, all stored in the separate
`allocator_state` mapping. Allocation walks `partial → empty → free → fresh`
slab lists; free validates the pointer, checks the canary, zeroes the slot, and
routes it through the quarantine.

**Large path.** Requests above the largest slab class become individual `mmap`
mappings wrapped in randomly-sized guard regions, recorded in a global
open-addressed hash table. Free re-maps the region `PROT_NONE` and holds it in a
two-stage quarantine (random 256-slot array → 1024-entry FIFO) before unmapping.

**Randomness.** Independent ChaCha8 CSPRNG instances per `(arena, size class)`,
per region allocator, and a transient init instance, each reseeded from the OS
`getrandom(2)` every 256 KiB. Used for slot selection, canary values, guard sizes,
quarantine indices, and region base offsets.

**Metadata protection.** All writable state is out-of-line behind high-entropy
bilateral guard regions; the only global writable symbol (`ro`) holds *pointers*
and is `mprotect`-read-only after init; optionally MPK-sealed (x86-64) or
protected by MTE (ARM).

---

## 5. Consolidated Findings

The complete, evidence-cited write-ups (description, impact, recommendation,
verified strengths, and per-subsystem claims assessment) are in the appendix
reports under [`findings/`](./findings/). The table below consolidates every
finding across all six subsystems.

> **Reading guide.** *Type* is as important as *Severity*. No finding is typed
> **Bug**. "Design-limitation" = an accepted/documented tradeoff. "Strength" =
> a property verified correct.

### 5.1 Findings of note (Low–Medium and above)

These are the items most worth an integrator's attention. **None is exploitable;**
all are accepted tradeoffs or low-priority hardening.

| ID | Sev | Type | Summary |
|---|---|---|---|
| **HARDEN-07** | Medium¹ | Design-limit | The `light` config disables the slab quarantine (incl. the "double free (quarantine)" check), the write-after-free scan, and slot randomization — substantially weakening *temporal* safety vs. `default`. Still stronger than stock allocators. |
| **HARDEN-01** | Low–Med | Design-limit | The 56-bit canary is **per-slab**, written verbatim to every slot. One same-slab info-leak discloses the canary for *all* slots in that slab (up to 256). Documented; absorption role unaffected. |
| **HARDEN-05** | Low–Med | Design-limit | The slab quarantine is a bounded ring; an attacker can force reuse of a target slot with ~`L` same-class frees. `L` shrinks to single digits (down to 1–2) for the largest size classes. |
| **CORE-01** | Low | Design-limit | `realloc` same-size fast path returns the pointer without slot/used/quarantine/canary validation (address-derived size class only). No mutation, no write primitive — a missed *detection* opportunity, not a bypass. |
| **LARGE-01** | Low | Design-limit | Large allocations ≥ 32 MiB (`REGION_QUARANTINE_SKIP_THRESHOLD`) skip the quarantine and are unmapped immediately — no UAF-detection window above the threshold. Deliberate VA-pinning cap. |
| **LARGE-02** | Low | Defense-in-depth | Page-sized *large* allocations reached only via over-aligned APIs (`posix_memalign(…, 8192, 100)`) get a deterministic 1-page guard (zero guard-size entropy). Normal `malloc` path unaffected; base ASLR intact. |
| **RNG-04** | Low | Design-limit | `getrandom(buf,n,0)` can block before the kernel pool is seeded — but this **fails closed** (never low-entropy; failure is fatal). Correct safety choice; noted as a boot-time dependency. |
| **RNG-05** | Low | Design-limit | OS reseed every 256 KiB bounds backtracking/prediction resistance to that window (ChaCha is invertible within a window). Reasonable, documented perf/security knob. |
| **RNG-07** | Low | Design-limit | `pthread_atfork`-based CSPRNG reseed does not cover `vfork`/raw `clone`. Such children almost always `exec` immediately. Inherent libc limitation. |
| **RNG-10** | Low | Design-limit | `get_random_bytes` bulk path (`size > 128`) writes keystream directly and **does not advance the `reseed` budget**. *Latent* (no >128-byte caller today); would weaken prediction resistance for a future bulk consumer. **Concrete one-line fix available.** |
| **HARDEN-02** | Low | Design-limit | Overflow into size-class **slack** (between requested size and the slot-end canary) is never detected. Inherent to size-class allocators; slack is intentionally an absorber. |
| **HARDEN-03** | Low | Design-limit | Canary integrity is verified only on free / size-query, never on the allocation fast path — so corruption of a long-lived neighbor is detected late. Documented ("checking on free will often be too late"). |
| **HARDEN-04** | Low | Design-limit | The write-after-free zero-scan is a reuse-time snapshot: bypassable by write-then-restore-zero and blind to zero-valued writes. A tripwire, not a guarantee. |
| **HARDEN-06** | Low | Design-limit | Zero-on-free and the WAF scan cover the *usable* region only, excluding the 8 canary bytes (benign — reset on reuse). |
| **MEM-03** | Low | Design-limit / DiD | ARM-MTE-only: `h_malloc_disable_memory_tagging` briefly re-RWs the `ro` page (one-byte store) under `full_lock`. Narrow, lock-protected; strictly weaker than the default build's always-writable metadata. |
| **MEM-04** | Low | Design-limit / DiD | With MPK explicitly enabled, a `pkey_alloc` failure **silently** degrades sealing to a no-op (fail-open to baseline isolation). **Recommend fail-closed.** |
| **MEM-06** | Low | Defense-in-depth | On `munmap` `ENOMEM`, `deallocate_pages` falls back to zeroing but leaves the region mapped RW (not `PROT_NONE`). Contents are zeroed (no leak); only triggers under map-count exhaustion. |
| **MTE-03** | Low | Design-limit | After a runtime MTE→off transition, slabs touched under MTE keep zeroed (inert) canaries until recycled. Documented tradeoff; no memory-safety regression. |
| **API-01** | Low | Design-limit | `malloc_usable_size`/`object_size` reveal the rounded size class (universal `malloc` property) but are **not** a metadata oracle — no canary/tag/guard/pointer is exposed, and corruption checks run first. |
| **DiD-01** | Low | Defense-in-depth | The `arm_mte_tags[]` bound (max 256 slots) lives only in comments. **Recommend a `static_assert`** so a future slot-count bump can't silently overflow the tag-history array. |

¹ `HARDEN-07` is *Medium relative to the `default` configuration*; the `light`
config remains far more secure than mainstream allocators.

### 5.2 Informational findings & verified strengths

The remaining ~30 items are informational. A substantial portion are **explicit
positives** — properties checked and confirmed correct — which is meaningful
evidence of the codebase's quality:

| ID | Type | Summary |
|---|---|---|
| RNG-01 | Strength | ChaCha8 keystream faithful to the DJB reference (constants, 8 rounds, LE words, feed-forward, 64-bit counter carry). |
| RNG-02 | Strength | Lemire uniform-range generators are **unbiased** (double-width product + correct `2^w mod bound` rejection); bounds enforced by `static_assert`/`#if`. |
| RNG-03 | Strength | All CSPRNGs eagerly OS-reseeded in `post_fork_child`; no identical parent/child streams. |
| RNG-06 | Design-limit | 56-bit per-slab canary, leading byte zeroed to contain C-string overflows — sound tradeoff. |
| RNG-08 | Design-limit | Guard size is page-granular; entropy scales with allocation size. `bound==0` degrades gracefully (no div-by-zero/UB). |
| RNG-09 | Strength | Per-instance CSPRNG correctly serialized under the owning size-class/region lock. |
| CORE-02 | Design-limit | Quarantine double-free diagnostic is exhaustive for *resident* entries; evicted re-frees still caught deterministically by `is_used_slot`. |
| CORE-03 | Design-note | `get_metadata` bounds-checks against `metadata_allocated`; the residual gap is safely covered by `PROT_NONE` pages + zero bitmaps. |
| CORE-04 | Design-note | In-slab offset is `u32`-divided — safe given `slab_size ≤ 131072`; recommend an explicit `static_assert`. |
| CORE-05 | Strength | `get_free_slot`/`get_mask` 64-bit boundary masking has no off-by-one. |
| CORE-06 | Strength | Per-class RNG correctly lock-protected and reseeded post-fork. |
| LARGE-03 | Defense-in-depth | `hash_page` is unkeyed — benign: lookups compare full pointers exactly and bases are ASLR-randomized. |
| LARGE-04 | Design-limit | `realloc` large in-place shrink has a benign TOCTOU reachable only under concurrent same-pointer API misuse (UB). |
| LARGE-05 | Design-limit | In-place `mremap` growth is intentionally dead code (`vma_merging_reliable = false`). |
| LARGE-06 | Design-limit | `usable_size`/`object_size` return the size-class-rounded size — standard and correct; no guard/canary bytes leaked. |
| MEM-01 | Design-limit | MPK metadata sealing is **off by default**; the default posture relies on out-of-line isolation + guard entropy + read-only pointer page. |
| MEM-02 | Design-limit | Per-size-class slab gap entropy (~23 bits) is uniform over the first 32 GiB of the 64 GiB envelope (by construction). |
| MEM-05 | Design-limit | MPK is per-thread PKRU; threads that never call the allocator run unsealed (inherent MPK limitation). |
| MEM-07 | Defense-in-depth | `slab_usable_size` is deliberately called while sealed — verified safe (`.rodata`-only); recommend a guarding comment. |
| MEM-08 | Defense-in-depth | Region hash-table grow-failure fallback mirrors MEM-06 (zeroed but left mapped). |
| MTE-01 | Strength | MTE tag-selection correct incl. slab edges — shift-by-one sentinel scheme, **no OOB** metadata access, all 4 exclusions applied, `IRG` always has ≥12 candidates. |
| MTE-02 | Strength | Free-time tag history intentionally retained — required for single-cycle UAF distinctness. |
| MTE-04 | Design-limit | `PROT_MTE` can't be cleared; the disable switch is consistent — no half-on / stale-tag state. |
| CPP-01 | Strength | Sized `operator delete` enforces size/alignment match → deterministic type-confusion tripwire; no false positives for over-aligned types. |
| CPP-02 | Strength | `operator delete(nullptr)` correct (no-op, no metadata lookup). |
| CPP-03 | Strength | `new`/`new[]` OOM + `new_handler` + `nothrow` handling standard-conforming. |
| API-02 | Strength | `free_sized`/`free_aligned_sized` reject wrong size/alignment deterministically (`fatal_error`), never silently. |
| API-03 | Strength | `calloc` multiply-overflow guarded by `__builtin_mul_overflow`; large-size canary/page-rounding overflows handled. |
| API-04 | Strength | Alignment validation (power-of-two, min-alignment, zero-reject) correct on every entry point. |
| DiD-02 | Defense-in-depth | Document `usable_size` rounding in the public header. |

---

## 6. Security Claims vs. Implementation Matrix

This is the heart of a claims-driven audit: every advertised property mapped to a
code-verified verdict.

**Legend:** ✅ Holds · 🟡 Holds with caveats · ➖ Not in scope / not exercised

| # | Claimed property (README) | Verdict | Evidence / caveat |
|---|---|:---:|---|
| 1 | Fully out-of-line metadata, reserved address space never reused | ✅ | Separate `allocator_state` + slab-region reservations; reached only by index arithmetic (`h_malloc.c:1000-1012,1273,1295`). |
| 2 | Global state read-only after init; pointers to isolated state | 🟡 | `ro` is `memory_protect_ro`'d and holds only pointers/pkey (`h_malloc.c:70-85,1332`). Caveat: narrow lock-protected RW window on ARM-MTE disable (MEM-03). |
| 3 | Allocator state in a dedicated region with high-entropy random guards | ✅ | ~24-bit CSPRNG-derived guard on **both** sides (`h_malloc.c:1270-1274`, `pages.c:8-29`). |
| 4 | MPK metadata protection on x86-64 (off by default) | 🟡 | Implemented & correctly bracketed across 51 seal/unseal sites; off by default (MEM-01), per-thread (MEM-05), fails open on `pkey_alloc` error (MEM-04). |
| 5 | MTE protection on ARMv8.5+ | ✅ | Random tags + reserved free-tag + neighbor-distinct tags; tag algebra OOB-safe at edges (MTE-01/02). |
| 6 | Deterministic detection of **any** invalid free | 🟡 | Holds for all real free paths (range/alignment/used/double-free/sized — `h_malloc.c:805-893`, `1430-1436`). Sole caveat: `realloc`-to-same-size identity fast path (CORE-01) — not a free, no mutation. |
| 7 | Validation of C++14 sized-deallocation size (type-confusion detect) | ✅ | `h_free_sized`/`h_free_aligned_sized` abort on class mismatch, wired from `new.cc` (CPP-01, API-02). |
| 8 | Isolated slab region; per-arena & per-size-class isolation; random bases | ✅ | Address-derived class/arena; independent random gap per class region (~23 bits, MEM-02). |
| 9 | No deterministic/low-entropy offsets to metadata or between size classes | ✅ | Random metadata guard + random per-class slab gap; no fixed user→metadata delta (CORE-01 strengths). |
| 10 | Slab region starts non-readable/non-writable; zero-size region stays `PROT_NONE` | ✅ | Slab region mapped `PROT_NONE`; per-slab unprotect gated on non-zero size; class 0 never unprotected (`h_malloc.c:1295,833`). |
| 11 | Slab allocations zeroed on free | 🟡 | True for the **usable** region under `ZERO_ON_FREE` (`h_malloc.c:846`); 8 canary bytes excluded (benign, HARDEN-06); via MTE store-zero when tagging on. |
| 12 | Write-after-free detection via zero-scan at allocation | 🟡 | Implemented (`h_malloc.c:494-512`); best-effort tripwire — bypassable by write-then-restore-zero, blind to zero writes (HARDEN-04); off in `light`. |
| 13 | Random slab canaries that absorb then later detect overflows | 🟡 | Placed after every slot; leading byte zeroed for C-strings. Caveats: per-slab reuse (HARDEN-01), slack not covered (HARDEN-02), free-time-only (HARDEN-03). |
| 14 | High-entropy per-slab canary values | 🟡 | 56-bit CSPRNG entropy per slab (`h_malloc.c:520`); "high entropy" is per-*slab*, not per-*slot* (HARDEN-01/RNG-06). |
| 15 | Delayed free via FIFO + randomization (slabs) | 🟡 | FIFO queue + random array exactly as described (`h_malloc.c:850-901`); bounded & flushable, shallow for large classes (HARDEN-05). |
| 16 | Proper double-free detection for quarantined allocations | ✅ | `is_quarantine_slot` (resident) + `is_used_slot` (evicted) — deterministic in both states (CORE-02). `default` only. |
| 17 | Large allocations tracked in a global address→size/guard hash table | ✅ | Open-addressed table; full-pointer comparison; statically reserved (`h_malloc.c:954,1108-1144`). |
| 18 | Large allocations purged + `PROT_NONE`-quarantined on free (UAF detect) | 🟡 | Two-stage random-array→FIFO quarantine implemented (`h_malloc.c:1016-1059`); ≥ 32 MiB skips it (LARGE-01). |
| 19 | Randomly-sized guard regions for large allocations | 🟡 | CSPRNG-randomized both sides, entropy scaling with size; deterministic 1-page guard only for over-aligned page-sized large allocs (LARGE-02). |
| 20 | CSPRNG = ChaCha8 keystream, per-domain instances, regularly OS-reseeded | 🟡 | Correct ChaCha8 (RNG-01), per-(arena,class)/region/init instances (RNG matrix); reseed every 256 KiB bounds the window (RNG-05); bulk-path accounting gap (RNG-10, latent). |
| 21 | Unbiased optimized random-range generation | ✅ | Lemire method, verified no modulo bias (RNG-02). |
| 22 | Errors other than `ENOMEM` from mm-syscalls treated as fatal | ✅ | Every `memory.c` wrapper fatals on non-`ENOMEM` (`memory.c:20-116`). |
| 23 | No legacy `brk` heap; no ASLR-interfering alignment tricks | ✅ | Pure `mmap`; over-alignment via map-slack + `munmap`-trim, kernel-randomized base (`pages.c:59-90`). |
| 24 | Fork safety (locks reset, CSPRNG reseeded) | 🟡 | `pthread_atfork` resets all locks + OS-reseeds all CSPRNGs (`h_malloc.c:1198-1233`); `vfork`/raw-`clone` not covered (RNG-07). |

**Summary:** Of 24 advertised properties, **11 hold unconditionally** and **13
hold with caveats** — where essentially every caveat is a *documented, inherent
tradeoff* of a probabilistic mitigation or a configuration knob, not an
implementation defect. **No claimed property was found to be false.**

---

## 7. Prioritized Recommendations

All recommendations are **low priority** — there is no exploitable issue to fix.
They are ordered by value as defensive / future-proofing improvements.

### Concrete code changes

1. **`RNG-10` — close the reseed-accounting gap (`random.c:54-74`).** In the
   `get_random_bytes` bulk branch, advance the reseed budget and re-key if the
   threshold is crossed, mirroring `refill`:
   ```c
   if (size > RANDOM_CACHE_SIZE / 2) {
       chacha_keystream_bytes(&state->ctx, buf, size);
       state->reseed += size;                    // <-- add accounting
       if (state->reseed >= RANDOM_RESEED_SIZE)  // (optional) re-key promptly
           random_state_init(state);
       return;
   }
   ```
   Latent today (no >128-byte caller), but the function is a general API and this
   restores the "reseed every 256 KiB" invariant for any future bulk consumer.

2. **`MEM-04` — fail closed on MPK setup failure (`h_malloc.c`, init).** When
   `CONFIG_SEAL_METADATA` is enabled, treat `pkey_alloc(0,0) == -1` as a
   `fatal_error` (or at least a one-time warning) instead of silently running
   with sealing disabled. A user who opted into MPK should not unknowingly lose
   it.

3. **`DiD-01` / `CORE-04` — anchor size-class invariants with `static_assert`.**
   Introduce `#define MAX_SLAB_SLOT_COUNT 256`, derive the `arm_mte_tags[]` size
   from it, and add:
   - `static_assert` that every `size_class_slots[i] <= MAX_SLAB_SLOT_COUNT`
     (guards the tag-history array against a future OOB write), and
   - `static_assert(max_slab_size_class <= UINT32_MAX, …)` (documents the
     `u32`-division invariant in the slot computation).

4. **`MEM-06` / `MEM-08` — prefer `PROT_NONE` on the `munmap`-`ENOMEM` fallback.**
   Before the purge/`memset` fallback, attempt `mprotect(PROT_NONE)` so a freed
   region becomes inaccessible rather than remaining mapped RW. Memory-safe
   today (contents are zeroed), but this restores fault-on-access.

5. **`CORE-01` — optionally validate the `realloc` same-size fast path.** Gate the
   identity return behind the same checks as `memory_corruption_check_small`
   (metadata derive, `slot_pointer == old`, `is_used_slot`, not quarantined,
   `check_canary`) so the one address-derived-size-class entry point doesn't trust
   an unvalidated pointer.

### Documentation clarifications

6. **`MEM-07`** — comment that `slab_usable_size`/`slab_size_class` must remain
   `.rodata`-only (no protected-metadata access) so they stay safe to call while
   MPK-sealed.
7. **`HARDEN-01`, `HARDEN-05`, `LARGE-01`, `HARDEN-06`, `DiD-02`** — make the
   following explicit in the README/headers: canary values are **per-slab**
   (one leak generalizes to the slab); quarantine depth shrinks to single digits
   for the largest slab classes; large allocations ≥ 32 MiB have **no** UAF
   quarantine window; the zero-on-free/WAF region excludes the canary bytes; and
   `malloc_usable_size` returns a **rounded** value.

### Deployment guidance

8. Prefer the **`default`** configuration where the threat model includes
   use-after-free / double-free. If `light` is required for performance, the
   single highest-value re-enable is the **slab quarantine** (restores reliable
   double-free detection and reuse delay), followed by **slot randomization**.
9. On x86-64 (no MTE), integrators able to absorb the cost should evaluate
   `CONFIG_SEAL_METADATA=true` to add a second line of defense beyond address
   secrecy for the metadata region.

---

## 8. Conclusion

`hardened_malloc` is a **robust, carefully-engineered, and honestly-documented**
security allocator. Across six independently-audited subsystems totaling ~3,400
lines of security-critical code, this review found **no memory-safety
vulnerabilities and no false security claims**. The architecture's central
guarantees — fully out-of-line and isolated metadata, deterministic invalid-free
and double-free detection, ASLR-friendly layout with high-entropy guard regions, a
cryptographically sound ChaCha8 CSPRNG with unbiased range generation, and a
correct ARM MTE tag scheme — were each verified against the source.

The findings that exist are, almost without exception, **inherent tradeoffs of a
probabilistic, performance-conscious hardening design** that the project already
documents: canaries that absorb more than they detect, quarantines that delay
rather than prevent reuse, and a CSPRNG reseed cadence tuned for performance. The
few concrete code suggestions (§7) are defensive, fail-closed, or future-proofing
improvements — not fixes for exploitable defects — and the most valuable of them
(the `RNG-10` reseed-accounting fix, the `MEM-04` fail-closed MPK setup, and the
`DiD-01` slot-count `static_assert`) guard against *latent* or *future* issues
rather than present ones.

A particularly positive signal for a security audit is the **density of
verified-correct strengths**: roughly half of the informational findings are
properties checked and confirmed sound (the ChaCha8 transcription, the Lemire
range generators, the MTE edge-slot tag algebra, the C++ sized-delete tripwire,
the integer-overflow surface, the fork-time reseed, the seal/unseal balance across
51 sites). This is consistent with a mature codebase that has received sustained
expert review.

**Bottom line:** GrapheneOS `hardened_malloc` at commit `9e88c14` delivers the
hardened security properties it advertises. Its claimed advantages over the stock
AOSP allocator are real and are correctly implemented in code.

---

## Appendix — Detailed Subsystem Reports

Full, evidence-cited findings (including every "Verified Strengths" and
per-subsystem "Claims Assessment") are in [`findings/`](./findings/):

| # | Subsystem | Report |
|---|---|---|
| 01 | Core slab allocator (alloc/free paths, metadata, bitmaps, locking) | [`findings/01-core-slab-allocator.md`](./findings/01-core-slab-allocator.md) |
| 02 | Large allocations & global region hash table + quarantine | [`findings/02-large-alloc-regions.md`](./findings/02-large-alloc-regions.md) |
| 03 | Randomness & CSPRNG (ChaCha8, Lemire ranges, reseed/fork) | [`findings/03-randomness-csprng.md`](./findings/03-randomness-csprng.md) |
| 04 | Canaries, quarantine & write-after-free | [`findings/04-canary-quarantine-waf.md`](./findings/04-canary-quarantine-waf.md) |
| 05 | Memory primitives, metadata isolation & MPK sealing | [`findings/05-memory-isolation-mpk.md`](./findings/05-memory-isolation-mpk.md) |
| 06 | Memory tagging (MTE), C++ allocator & API surface | [`findings/06-mte-cpp-api.md`](./findings/06-mte-cpp-api.md) |

### Audit metadata

- **Target commit:** `9e88c14305440c45551789c284c1de08ec08e451`
- **Reproduce the checkout:** `git clone https://github.com/GrapheneOS/hardened_malloc && git -C hardened_malloc checkout 9e88c14`
- **Configurations:** `config/default.mk`, `config/light.mk`
- **Nature of audit:** static source review; no dynamic analysis or on-hardware MTE execution was performed (see §2.2).

> *This report is an AI-assisted security audit produced for research and
> educational purposes. It documents a point-in-time source review and is not a
> guarantee of the absence of vulnerabilities. Findings should be independently
> validated before being relied upon.*
