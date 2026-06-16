# Large Allocations & Region Table — Audit Findings

Audit target: GrapheneOS hardened_malloc @ commit `9e88c14305440c45551789c284c1de08ec08e451`
Subsystem: large-allocation path, global region hash table, large-allocation quarantine.
Config audited: `config/default.mk` (default) and `config/light.mk`.
Files: `h_malloc.c`, `pages.c`, `pages.h`, `memory.c`, `memory.h`, `random.c`, `random.h`, `util.h`.

Reviewer stance: defensive, evidence-based. Findings are classified as **Bug** (real defect), **Design-limitation** (documented/inherent tradeoff), or **Defense-in-depth** (hardening suggestion). This subsystem is **strong**; the substantive findings are design tradeoffs and minor entropy/robustness observations rather than exploitable bugs.

---

## Subsystem Overview

Large allocations (request size `> max_slab_size_class`, i.e. `> 128 KiB` with `CONFIG_EXTENDED_SIZE_CLASSES`, else `> 16 KiB`) are standalone anonymous `mmap` mappings, each surrounded by a randomly-sized guard region on both sides. They are tracked in a global open-addressed hash table keyed by the usable pointer:

- **Allocation** (`allocate_large`, `h_malloc.c:1387`): round size to a large size class (`get_large_size_class`, `:1367`), pick a random guard size under the region lock (`get_guard_size`, `:1383`), `allocate_pages` the mapping (`pages.c:13`), then `regions_insert` (`:1108`) the `{p, size, guard_size}` tuple.
- **Deallocation** (`deallocate_large`, `h_malloc.c:1422`): `regions_find` (`:1131`) the pointer (NULL ⇒ `fatal_error("invalid free")`), `regions_delete` (`:1144`), then `regions_quarantine_deallocate_pages` (`:1016`).
- **Region table**: two statically-reserved buffers (`regions_a`/`regions_b`, `:1008`-`1010`) of `MAX_REGION_TABLE_SIZE` entries each; the table doubles in place via `regions_grow` (`:1062`), rehashing into the alternate buffer and `MADV_DONTNEED`-purging the old one. Linear probing in the **decreasing** index direction; load factor kept `< 75%` (grow when `free*4 < total`, `:1111`). Hash is the keyless `hash_page` (`pages.h:23`).
- **Quarantine** (`regions_quarantine_deallocate_pages`, `:1016`): freed mapping is re-`mmap`'d `PROT_NONE` (`MAP_FIXED`) and purged, then pushed through a two-stage structure — a random-slot array (`REGION_QUARANTINE_RANDOM_LENGTH`, default 256) feeding a FIFO ring buffer (`REGION_QUARANTINE_QUEUE_LENGTH`, default 1024). The mapping evicted from the tail is `munmap`'d. Allocations `>= REGION_QUARANTINE_SKIP_THRESHOLD` (32 MiB) skip the quarantine and are unmapped immediately.
- **realloc large side** (`h_realloc`, `:1550`): exact-size match is a no-op; in-place shrink remaps the guard and quarantines the tail; in-place mremap growth is compiled out (`vma_merging_reliable = false`, `:1621`); otherwise allocate-new + copy + free-old, with an `mremap(MREMAP_MAYMOVE|MREMAP_FIXED)` fast path for copies `>= 32 MiB`.

Integer-overflow safety is layered: `get_large_size_class` returns 0 on page-rounding overflow; `add_guards` (`pages.c:8`) uses `__builtin_add_overflow` for `size + 2*guard_size`; `h_calloc` uses `__builtin_mul_overflow`. mmap/mremap/munmap/mprotect wrappers (`memory.c`) treat every non-`ENOMEM` error as fatal.

---

## Findings

### LARGE-01 — Large allocations ≥ 32 MiB bypass the quarantine (no UAF detection window)
- **Severity:** Low
- **Type:** Design-limitation (documented tradeoff)
- **Location:** `h_malloc.c:1016`-`1020` (`regions_quarantine_deallocate_pages`), threshold `REGION_QUARANTINE_SKIP_THRESHOLD = 33554432` (`config/default.mk:18`).
- **Description:** `if (!REGION_QUARANTINE || size >= REGION_QUARANTINE_SKIP_THRESHOLD) { deallocate_pages(...); return; }`. For any large allocation of 32 MiB or more, the mapping (usable region + both guards) is `munmap`'d immediately on free rather than being kept reserved `PROT_NONE` in the quarantine.
- **Security Impact:** Use-after-free against a freed ≥32 MiB allocation is **not** deterministically caught by the quarantine: the address range is returned to the kernel and can be re-mapped by a subsequent large allocation (or any other mapping), so a stale pointer may resolve to attacker-controlled or unrelated data instead of faulting. The guard regions and the exact-pointer `regions_find` check still defend against many OOB and invalid-free cases, and immediate `munmap` does remove the data — so this is a reduction in UAF *detection*, not a confidentiality leak. The threshold is a deliberate cap to avoid pinning tens of GiB of address space (the quarantine can hold up to ~1280 mappings; 1280 × 32 MiB ≈ 40 GiB of reserved VA if it did not skip). The README documents this knob (`README.md:317`).
- **Recommendation:** Accept as a tradeoff; document the security implication explicitly next to the config knob (the README currently describes the knob mechanically without noting the UAF-detection gap). Deployments that allocate large buffers in a fixed band could lower the threshold, accepting the VA cost. No code change required.

### LARGE-02 — Deterministic single-page guard for page-sized large allocations obtained via over-aligned allocation APIs
- **Severity:** Low
- **Type:** Defense-in-depth (entropy edge case)
- **Location:** `get_guard_size` (`h_malloc.c:1383`-`1385`); reached with a tiny `size` only through `allocate_aligned` (`:1463`, `:1471`) when `alignment > PAGE_SIZE`.
- **Description:** `get_guard_size` computes the random bound as `size / PAGE_SIZE / GUARD_SIZE_DIVISOR` and returns `(get_random_u64_uniform(state, bound) + 1) * PAGE_SIZE`. For a one-page allocation (`size == PAGE_SIZE`, `GUARD_SIZE_DIVISOR == 2`) the bound is `4096/4096/2 == 0`. `get_random_u64_uniform(state, 0)` returns 0 (the `u128` `0 >> 64` is well-defined), so the guard size is a fixed `1 * PAGE_SIZE` with **zero entropy**. The normal `malloc`/`calloc` path can never trigger this because `allocate()` (`:1418`) routes any `size <= max_slab_size_class` (≥16 KiB) to the slab allocator, so the smallest *normal* large allocation has bound `≥ 2`. However, `allocate_aligned`'s `alignment > PAGE_SIZE` branch unconditionally calls `get_large_size_class(size)` (`:1463`) for *any* request size, so `posix_memalign(p, 8192, 100)`, `aligned_alloc(8192, 100)`, `memalign`, and `valloc`-style calls can produce a page-sized large allocation whose guards are deterministic 1-page regions on both sides.
- **Security Impact:** Low. The guard *size* randomization ("how many pages of guard") is one of several entropy sources; the dominant ASLR entropy is the mapping *base address*, which is unaffected. A deterministic 1-page guard merely makes the distance from the usable region to the next mapping predictable for these specific small-but-large allocations — only marginally useful to an attacker who already knows/leaks the base. It does not weaken invalid-free detection or the quarantine.
- **Recommendation:** Optionally enforce a minimum random bound (e.g. `max(bound, 1)` so `get_random_u64_uniform` always has ≥1 unit of slack, or clamp the smallest large size used for guard computation) so even page-sized large allocations get ≥1 page of *randomized* guard variation. Cosmetic hardening only.

### LARGE-03 — `hash_page` is a fixed, unkeyed hash (no per-process secret)
- **Severity:** Informational
- **Type:** Defense-in-depth
- **Location:** `hash_page` (`pages.h:23`-`30`); used by `regions_insert`/`find`/`delete`/`grow`.
- **Description:** The region table hash is a fixed multiplicative mix of the page frame number (`(uintptr_t)p >> 12`) with no random seed. Unlike many hardened hash tables, there is no secret key folded into the hash.
- **Security Impact:** Negligible for correctness/security. (1) The table stores and compares **full pointers** exactly (`regions_find` returns a hit only when `r == p`, `:1141`), so an adversary cannot cause a *mis-resolution* (one allocation's lookup returning another's metadata) regardless of hash collisions. (2) A collision-flooding DoS would require the attacker to place many large allocations at addresses that collide modulo the table size; large-allocation base addresses are ASLR-randomized (kernel mmap randomization plus the random metadata/slab gaps, `:1271`, `:1311`), so the attacker does not control the low bits that drive the bucket index, and the table grows with bounded load factor so probe chains stay short. The hash is therefore correctness-bearing, not security-bearing, and its secrecy is not relied upon. Worth recording only so future changes do not start *depending* on hash secrecy without adding a key.
- **Recommendation:** No change required. If the table is ever exposed to adversary-chosen keys, add a per-process random seed (already available via `ra->rng`).

### LARGE-04 — realloc large in-place shrink updates region size after unlocking and re-mapping (benign TOCTOU on concurrent same-pointer misuse)
- **Severity:** Informational
- **Type:** Design-limitation
- **Location:** `h_realloc` in-place shrink, `h_malloc.c:1595`-`1618`.
- **Description:** The shrink path looks up the region under `ra->lock`, reads `old_size`/`old_guard_size`, then **unlocks** (`:1593`), performs `memory_map_fixed(new_end, old_guard_size)` for the relocated guard (`:1599`) and `regions_quarantine_deallocate_pages(new_guard_end, old_size - size, 0)` for the freed tail (`:1605`), and only afterward re-locks to set `region->size = size` (`:1607`-`1614`). During the unlocked window the table still advertises the old (larger) size while the tail is already being quarantined/unmapped.
- **Security Impact:** None under correct API usage. Reaching this state requires another thread to operate on the **same** allocation pointer concurrently with the `realloc` — which is undefined behavior / a data race at the allocator's API contract (concurrent `realloc`/`free`/`malloc_usable_size` on one live pointer). A racing `h_malloc_usable_size`/`h_malloc_object_size` could observe the stale larger size and a racing access could touch the now-protected tail, but the root cause is caller misuse, not an allocator defect. The shrink re-validates the region after re-locking (`regions_find` again, `fatal_error` if vanished, `:1608`-`1611`), so the allocator's own invariants are preserved.
- **Recommendation:** No change required. If desired for strictness, the size update could be performed before releasing the lock for the tail operation, but that lengthens the lock hold time for no real-world safety benefit.

### LARGE-05 — In-place large-growth via `mremap` is dead code (`vma_merging_reliable = false`)
- **Severity:** Informational
- **Type:** Design-limitation (intentional)
- **Location:** `h_malloc.c:1620`-`1672`; gate `static const bool vma_merging_reliable = false;` (`:1621`).
- **Description:** The in-place growth branch using `memory_remap` (`:1626`) is guarded by a compile-time-`false` constant and is never executed; large growth always falls through to the copy path (allocate-new + `memcpy` + free-old, `:1645` onward). The comment and the `MREMAP_MOVE_THRESHOLD` machinery indicate the in-place/`mremap` move is intentionally disabled because VMA merging behavior is not relied upon.
- **Security Impact:** None. This is a conservative posture (avoids `mremap`-related aliasing/merging surprises). Noted so the reader does not mistake the dead branch for an active code path. The active ≥32 MiB copy path uses `memory_remap_fixed` (`MREMAP_MAYMOVE|MREMAP_FIXED`, `memory.c:102`) and correctly deletes the old region from the table before the move (`:1658`); since ≥32 MiB it skips quarantine anyway (consistent with LARGE-01).
- **Recommendation:** None.

### LARGE-06 — Page-rounded `usable_size`/`object_size` for large allocations may slightly over-report writable bounds
- **Severity:** Informational
- **Type:** Design-limitation
- **Location:** `h_malloc_usable_size` (`h_malloc.c:1871`), `h_malloc_object_size` (`:1934`-`1935`).
- **Description:** Both return `region->size`, which is the **size-class-rounded** size (`get_large_size_class`), e.g. a 200 KiB request with `CONFIG_LARGE_SIZE_CLASSES` rounds up to a power-of-2-spacing class and the whole rounded size is reported. This is standard and correct `malloc_usable_size` semantics (the rounded bytes *are* usable, the full mapping is `PROT_READ|WRITE`). Unlike the small path there is no canary to subtract (`adjust_size_for_canary` adds nothing for large sizes, `:1492`-`1496`), so returning `region->size` directly is correct.
- **Security Impact:** None beyond the inherent property of `malloc_usable_size` that callers using it to size writes get access to the full rounded extent (true of all allocators). No guard/quarantine bytes are ever included.
- **Recommendation:** None.

---

## Verified Strengths

- **Layered integer-overflow defense on the size + guard computation.** `get_large_size_class` returns 0 on page-align overflow and every caller checks it (`allocate_large:1389`, `allocate_aligned:1464`, `h_realloc:1558`). The `size + 2*guard_size` sum is computed with `__builtin_add_overflow` twice in `add_guards` (`pages.c:8`-`11`), and the aligned path additionally overflow-checks `usable_size + (alignment - PAGE_SIZE)` (`pages.c:40`). `h_calloc` guards the multiply (`:1533`). A near-`SIZE_MAX` request cannot wrap into a small mapping; it fails with `ENOMEM`. **The claimed overflow safety holds.**
- **Deterministic invalid-free / invalid-realloc detection for large pointers.** `deallocate_large` (`:1430`), `h_realloc` (`:1583`), `h_malloc_usable_size` (`:1868`) all `fatal_error` when `regions_find` returns NULL, and the lookup compares the *full* pointer (`:1137`-`1141`), so any pointer not exactly matching a live large allocation base is reliably rejected. Combined with the slab-region range check in `h_free`/`h_free_sized` (`:1728`, `:1755`), a wild/non-heap pointer passed to `free` is deterministically caught. **Supports the "deterministic detection of any invalid free" claim for the large path.**
- **Two-stage quarantine genuinely keeps freed regions `PROT_NONE` for a meaningful window.** On free the mapping is re-`mmap`'d `PROT_NONE` over its own address (`memory_map_fixed`, `:1022`) and purged (`:1023`), then must traverse a random-slot array (256) *and then* a FIFO queue (1024) before being `munmap`'d (`:1037`-`1059`). If the random slot it lands in was empty, the region simply *stays* reserved and nothing is unmapped (`:1041`-`1044`), maximizing retention. The eviction-into-`target`/`munmap`-the-displaced-mapping structure is correct: a region is never unmapped on the same call that quarantines it (except the size-skip path). **Supports the UAF-detection-via-quarantine claim** (modulo the documented ≥32 MiB skip, LARGE-01).
- **Open-addressing table is correctly sized and probe-terminating.** Load factor is bounded below 75% (`free*4 < total` ⇒ grow, `:1111`), so a NULL sentinel always exists and `regions_find`/`insert` probe loops terminate (`:1120`, `:1137`). `regions_grow` rehashes the live entries into the alternate static buffer with the new mask, then purges/zeros the old buffer (`:1084`-`1101`) — correct and allocation-free (no dynamic mmap, honoring the "statically reserved metadata" claim). `regions_delete` implements the textbook backward-shift deletion adapted to the decreasing-probe direction (the three-clause cyclic interval test at `:1162`), preserving lookup correctness after removal.
- **mmap/mremap/munmap/mprotect failure handling is fail-closed.** Every wrapper in `memory.c` calls `fatal_error` on any error other than `ENOMEM` (`:21`-`23`, `:43`-`45`, `:62`-`64`, `:74`-`76`, `:96`-`98`, `:105`-`107`, `:114`-`115`). An unexpected `MAP_FIXED`/`mprotect` failure that could otherwise leave a region in an inconsistent (e.g. readable-but-freed) state aborts the process instead. The quarantine's `memory_map_fixed` failure path degrades safely to purge-or-memset (`:1022`-`1025`) rather than leaving stale data readable.
- **Guard size uses the CSPRNG.** `get_guard_size` draws from `ra->rng`, a per-allocator ChaCha-based `random_state` seeded from `getrandom(2)` (`random.c:27`-`34`) and reseeded every 256 KiB (`random.c:46`); the draw is under `ra->lock` (`:1396`-`1398`). Apart from the LARGE-02 page-sized corner case, guard sizes are uniformly random in `[1, size/PAGE_SIZE/GUARD_SIZE_DIVISOR]` pages — high entropy that scales with allocation size.
- **Fork safety is handled.** `pthread_atfork(full_lock, full_unlock, post_fork_child)` (`:1340`) acquires the region lock (and all slab locks) across fork (`:1198`-`1218`); the child re-initializes the region lock **and reseeds `ra->rng`** (`post_fork_child`, `:1223`-`1224`) so parent and child do not share guard-size/quarantine-index randomness. No `brk` is used anywhere; large allocations are pure `mmap` (honoring "no legacy brk heap" / "no alignment tricks interfering with ASLR").
- **No alignment tricks that leak into ASLR.** Over-aligned large allocations trim the lead/trailing slack with `munmap` (`pages.c:68`-`80`) and store the true base + symmetric `guard_size`, so `deallocate_pages` unmaps exactly the live mapping (`pages.c:85`-`90`). The mapping base remains a kernel-randomized `mmap` address.

---

## Claims Assessment

| Claim | Verdict | Justification |
|---|---|---|
| "Large allocations are tracked via a global hash table mapping their address to their size and random guard size." | **Holds** | `struct region_metadata {p, size, guard_size}` (`:954`) stored in the open-addressed table; `regions_insert` records all three (`:1124`-`1126`); guard size is CSPRNG-derived (`:1397`). |
| "Large allocations are purged and memory protected on free with the memory mapping kept reserved in a quarantine to detect use-after-free" (FIFO ring buffer + random-slot array swap). | **Holds-with-caveats** | The purge + `PROT_NONE` remap + random-array→FIFO-queue structure is implemented exactly as described (`:1016`-`1059`). Caveat: allocations `>= 32 MiB` skip the quarantine and are unmapped immediately (LARGE-01), so the UAF-detection guarantee applies only below `REGION_QUARANTINE_SKIP_THRESHOLD`. |
| "Randomly sized guard regions for large allocations" (`CONFIG_GUARD_SIZE_DIVISOR`). | **Holds-with-caveats** | CSPRNG-randomized guard pages on both sides, entropy scaling with size (`get_guard_size:1383`, applied in `allocate_pages:24`/`allocate_pages_aligned`). Caveat: page-sized large allocations reachable only via over-aligned APIs get a deterministic 1-page guard (zero entropy) due to bound==0 (LARGE-02); the normal `malloc` path is unaffected. |
| "Deterministic detection of any invalid free (unallocated, unaligned, etc.)" — non-region pointer reliably rejected. | **Holds** (large path) | A non-matching pointer makes `regions_find` return NULL ⇒ `fatal_error("invalid free")` (`:1430`-`1432`); full-pointer comparison precludes false matches; the slab-vs-large dispatch is a strict address-range test (`:1728`). A wild pointer outside all regions is deterministically caught. |
| "Large allocations are the only dynamic memory mappings … allocator state … is statically reserved." | **Holds** | The region table lives in `regions_a`/`regions_b` inside the statically `mmap`'d `allocator_state` (`:1004`-`1010`, `:1273`); `regions_grow` reuses the alternate static buffer and never `mmap`s new metadata (`:1077`-`1104`). Only `allocate_pages` for user data maps dynamically. |
| "No usage of the legacy brk heap" / "No alignment tricks interfering with ASLR". | **Holds** | All large allocations use `mmap(MAP_ANONYMOUS|MAP_PRIVATE)` (`memory.c:19`, `:41`); no `sbrk`/`brk` in the tree. Over-alignment is achieved by mapping slack and `munmap`-trimming (`pages.c:59`-`80`), preserving a kernel-randomized base. |
| Integer-overflow safety of `size + 2*guard_size` and page rounding for near-`SIZE_MAX` requests. | **Holds** | `get_large_size_class`→0 on overflow with caller checks; `add_guards` double `__builtin_add_overflow` (`pages.c:8`); aligned-slack and calloc multiply also overflow-checked. No wrap into an undersized mapping. |
| Hash table cannot be forced to mis-resolve a lookup or behave pathologically. | **Holds-with-caveats** | Exact full-pointer comparison prevents mis-resolution; bounded load factor guarantees probe termination and short chains. Caveat: the hash is unkeyed (LARGE-03); this is acceptable because security does not depend on hash secrecy and addresses are ASLR-randomized, but it is a latent assumption to preserve. |

---

## Bottom line

The large-allocation path and region table are a **robust, defensively-engineered** subsystem. Overflow handling is layered and fail-closed, invalid-free detection is deterministic and exact, the two-stage quarantine provides a genuine UAF-detection window, and mmap-family error handling aborts rather than degrading to an unsafe state. The findings are dominated by **documented design tradeoffs** (≥32 MiB quarantine skip) and **minor entropy/robustness observations** (deterministic guard for over-aligned page-sized allocations, unkeyed hash, benign concurrent-misuse TOCTOU in realloc shrink). No memory-safety bug or exploitable defect was identified in this subsystem.
