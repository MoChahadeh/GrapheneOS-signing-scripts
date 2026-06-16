# Core Slab Allocator — Audit Findings

- **Target**: GrapheneOS `hardened_malloc`, commit `9e88c14305440c45551789c284c1de08ec08e451`
- **Subsystem**: SMALL/SLAB allocator hot paths and slab metadata management
- **Primary file**: `h_malloc.c` (supporting: `util.h`, `mutex.h`, `pages.h`, `memory.h`, `memory.c`, `memtag.h`, `third_party/libdivide.h`)
- **Configuration reviewed**: `config/default.mk` (full hardening) and `config/light.mk`
- **Scope**: `allocate_small`, `deallocate_small`, slab metadata management, bitmap operations, slot/geometry helpers, slab-list management, the per-size-class locking model, fork safety, and invalid-free/double-free detection.

## Subsystem Overview

The small allocator partitions a single large `PROT_NONE` "slab region" into `N_ARENA` arenas, each holding `N_SIZE_CLASSES` *class regions* of `REAL_CLASS_REGION_SIZE` (= 2 × 32 GiB) bytes. Within a class region the usable portion is `CLASS_REGION_SIZE` (32 GiB), with a per-class random page-granular `gap` (line 1310-1312) placed before `class_region_start`, so the start of usable slabs is at a randomized, non-deterministic offset. Crucially, the slab *metadata* (`struct slab_metadata`, line 117) is stored in a completely separate mapping (`slab_info_mapping`, line 1000-1012), reached only by index arithmetic `c->slab_info + index`; there are no metadata pointers, sizes, or free-list links stored inside the user-accessible slab memory. This satisfies the "fully out-of-line metadata" claim and removes the canonical inline-metadata corruption primitive.

Each slab is an array of fixed-size slots. Allocation state is tracked by a 256-bit free bitmap (`u64 bitmap[4]`) plus, when `SLAB_QUARANTINE` is enabled, a parallel 256-bit `quarantine_bitmap[4]`. `MAX_SLAB_SLOT_COUNT` is 256 and the largest `size_class_slots[]` entry is 256, so four `u64` words exactly cover every size class. Allocation walks per-size-class lists in priority order: `partial_slabs` (doubly-linked LIFO) → `empty_slabs` (cached, singly-linked LIFO) → `free_slabs` (purged/`PROT_NONE`, FIFO) → fresh `alloc_metadata`. Deallocation reverses these transitions and, for quarantine builds, routes the freed pointer through a random + FIFO queue so the slot is not immediately reusable.

The locking model is coarse and simple: each `struct size_class` has its own `pthread_mutex_t` (`mutex.h`), and **every** read or write of mutable slab state (bitmaps, list heads, `empty_slabs_total`, the per-class `rng`, the quarantine queues, `metadata_count`) occurs while that lock is held. The `ro` structure containing region bases, divisors, and per-class immutable geometry is made read-only via `mprotect` after init (line 1332) and is never mutated on the hot path, so it needs no locking. Fork safety is handled by `pthread_atfork(full_lock, full_unlock, post_fork_child)` (line 1340), which acquires every lock before fork and re-initializes them in the child.

**Overall assessment: this subsystem is robust and well-engineered.** The invalid-free and double-free detection paths are deterministic and ordered so that every adversary-controlled-pointer rejection happens *before* any metadata mutation or user-memory write. The integer/pointer arithmetic is carefully sized (u64 divisor for the >u32 region offset; u32 divisor for the bounded in-slab offset), and I found no off-by-one in bitmap indexing, slot computation, or list transitions. I identified **no memory-safety vulnerabilities**. The findings below are one low-severity behavioral gap in `realloc`'s same-size fast path, plus informational notes and defense-in-depth observations. The claimed security properties for this subsystem hold (one with a documented caveat noted under CORE-01).

## Findings

### CORE-01 — `realloc` same-size fast path skips slot/quarantine/canary validation

- **Severity**: Low
- **Type**: Design-limitation (documented behavioral gap)
- **Location**: `h_malloc.c:1569-1573` (`h_realloc`), with the helper `slab_usable_size` at `h_malloc.c:775-777` and `slab_size_class` at `h_malloc.c:765-773`.

**Description.** When `old` lies in the slab region, `h_realloc` computes `old_size = slab_usable_size(old)` and, if `get_size_info(size).size == old_size`, returns `old_orig` immediately:

```c
old_size = slab_usable_size(old);
if (size <= max_slab_size_class && get_size_info(size).size == old_size) {
    return old_orig;
}
```

`slab_usable_size` → `slab_size_class` derives the size class purely from the pointer's *address bits* (`offset / ARENA_SIZE`, `offset / REAL_CLASS_REGION_SIZE`); it performs **no** `get_metadata`, `is_used_slot`, `is_quarantine_slot`, alignment, or canary check. Consequently, an in-region pointer that is unaligned, points mid-slot, points into a not-yet-used or freed/quarantined slot, or points into a guard slab will be returned unchanged by this fast path instead of being diagnosed, as long as the caller's requested `size` maps to the same size class. The contrast is deliberate elsewhere: the corresponding `h_malloc_usable_size` path *does* run the full `memory_corruption_check_small` (line 1855), and the realloc *slow* path eventually calls `deallocate_small(old, ...)` (line 1687) which validates fully.

**Security Impact.** Low and tightly bounded. No metadata is mutated and no out-of-bounds write occurs on this path — it returns the caller's own pointer. The only consequence is a *missed detection opportunity*: a same-size `realloc` of an invalid/quarantined slab pointer is silently accepted rather than aborting with `fatal_error`. It does not create a write primitive, does not bypass quarantine for subsequent frees (a later `free` of the same pointer still goes through `deallocate_small`'s full checks), and does not affect allocations of other slots. It is best characterized as a hardening gap in the "deterministic detection of any invalid free" posture (realloc-as-identity is not strictly a free, but it is a use). This matches the allocator's documented stance that `realloc` preserving the same size class is an intentional fast path.

**Recommendation (defense-in-depth).** Optionally gate the fast-path return behind the same validation used by `memory_corruption_check_small` (derive metadata, verify `slot_pointer(...) == old`, `is_used_slot`, not quarantined, `check_canary`) under the size-class lock before returning `old_orig`. This adds one locked metadata probe to the same-size realloc path; given realloc-to-same-size is comparatively rare, the cost is acceptable and it closes the only small-allocator entry point that trusts an address-derived size class without a metadata check.

### CORE-02 — Quarantine displacement makes the "double free (quarantine)" diagnostic probabilistic, not exhaustive (by design)

- **Severity**: Informational
- **Type**: Design-limitation (documented tradeoff)
- **Location**: `h_malloc.c:850-901` (quarantine handling in `deallocate_small`); slot re-derivation at `h_malloc.c:896-900`.

**Description.** On free, the slot is marked in `quarantine_bitmap` (`set_quarantine_slot`, line 855) and the pointer is inserted into the random array and/or FIFO queue. A *displaced* victim pointer (`random_substitute` / `queue_substitute`) is the one actually returned to the slab. For that displaced pointer, the metadata/slab/slot are re-derived (line 896-898) and `clear_quarantine_slot` + `clear_used_slot` are applied. This is correct and self-consistent. The double-free guard `is_quarantine_slot` (line 851) deterministically catches a re-free of a pointer that is *still resident* in the quarantine, which is the common, near-term double-free case the feature targets.

**Security Impact.** None beyond the documented model. Once a freed pointer has been *evicted* from the quarantine (displaced back into the slab as a free slot), a subsequent double free of that original pointer is caught by the `is_used_slot` check (line 829) rather than the quarantine check — i.e., it is still caught deterministically as "double free", just via the other guard. The quarantine's purpose is delaying reuse and catching *prompt* double-frees/UAF, not providing unbounded double-free memory. There is no window in which a double free goes *undetected*: every free re-validates `is_used_slot` and `is_quarantine_slot` under the lock before clearing any bit. I confirmed there is no state where both bitmaps say "free" yet the slot is handed out.

**Recommendation.** None required; behavior matches the design intent and the "proper double-free detection for quarantined allocations" claim holds for resident entries. Documenting (in code comments) that post-eviction double-frees fall back to the `is_used_slot` guard would aid future reviewers.

### CORE-03 — `get_metadata` bounds check uses `metadata_allocated`, not `metadata_count`; relies on PROT_NONE + bitmap for the residual gap

- **Severity**: Informational
- **Type**: Design observation (defense-in-depth note)
- **Location**: `h_malloc.c:480-488` (`get_metadata`), `h_malloc.c:339-368` (`alloc_metadata`), guard-slab skip at `h_malloc.c:363-366`.

**Description.** `get_metadata` rejects `index >= c->metadata_allocated` (line 484). `metadata_allocated` is the number of metadata entries whose backing pages have been made RW (grown in page-sized chunks, line 346-353), which is `>= metadata_count` (the number of slabs actually handed to the geometry) and can exceed it by up to a page of entries minus one. Therefore a forged pointer whose address maps to an index in the half-open range `[metadata_count, metadata_allocated)` — a metadata slot that is *allocated/zeroed but not yet backing a live slab* — passes the `get_metadata` bounds check. The comment at line 483 ("still caught without this check either as a read access violation or 'double free'") documents the intended layered defense.

**Security Impact.** None — the residual range is still safe through two independent mechanisms:
1. Such a metadata entry is zero-initialized, so its `bitmap[*]` is all-zero; `is_used_slot` returns false (line 829) → deterministic `fatal_error("double free")` before any mutation. No write to user memory or metadata occurs first (the zeroing/canary block at 833-848 runs only `if (likely(!is_zero_size))` *after*... — correction: the `is_used_slot` check at 829 precedes the canary/zero block at 833, so rejection happens first). Re-verified: order is alignment check (825) → `is_used_slot` (829) → canary/zero (833). Good.
2. The corresponding slab pages were never `memory_protect_rw`'d (they are only mapped RW in `alloc_metadata` line 358 or the `free_slabs`/`empty_slabs` reuse paths), so any *read* of canary/user bytes at that address would fault on `PROT_NONE` memory.

Guard slabs (the extra index consumed at line 363-366 every `GUARD_SLABS_INTERVAL` slabs) are likewise never made RW and are never selected for allocation, so a pointer into a guard slab is rejected by `is_used_slot` (its bitmap is zero) and would fault on access. I confirmed allocation never assigns slots in guard-slab indices.

**Recommendation.** None required; the layering is sound and intentional. As a micro-hardening, `get_metadata` *could* additionally compare against `metadata_count` to fail a hair earlier, but this would not change the security outcome and would add a field read to the hot path. Leave as-is.

### CORE-04 — In-slab offset is truncated to `u32` for slot division; safe given slab-size bounds (verify-on-change)

- **Severity**: Informational
- **Type**: Design observation
- **Location**: `h_malloc.c:823` and `:898` (`libdivide_u32_do((char *)p - (char *)slab, &c->size_divisor)`), `slot_pointer` at `:490-492`, geometry at `:265-267`, `:480-488`.

**Description.** Slot index is computed as a **u32** division: `libdivide_u32_do((char *)p - (char *)slab, &c->size_divisor)`. The numerator is the offset of `p` within a single slab. This is only safe if `slab_size` never exceeds `UINT32_MAX`. I verified the bound: the maximum `slab_size` is `page_align(slots * size)`. With extended size classes the largest `size` is 131072 with `slots == 1` → `slab_size == 131072`; the largest slot count (256) occurs only at `size == 16` → `slab_size == 4096`. Across all classes `slab_size <= 131072`, far below `UINT32_MAX`. Because `get_metadata` (which uses the **u64** `slab_size_divisor` on the up-to-32 GiB region offset, line 482) has already constrained `index < metadata_allocated` and `get_slab` recomputes `slab = class_region_start + index*slab_size`, the difference `p - slab` is in `[0, slab_size)` and fits in u32 with no truncation. The split — u64 divisor for the region-wide offset, u32 divisor for the in-slab offset — is correct and not interchangeable.

**Security Impact.** None under any current or reachable configuration. The result `slot` is immediately validated by `slot_pointer(size, slab, slot) != p` (line 825), so even a hypothetical mis-division would be caught before any metadata write. The note exists only because the u32 numerator is an *implicit invariant*: if a future change pushed a single slab's size past 4 GiB (e.g., a pathological `slots * size`), the truncation would silently produce a wrong-but-still-validated slot. The existing `static_assert`s (e.g., page-size assumption at line 326) do not directly assert `slab_size <= UINT32_MAX`.

**Recommendation (defense-in-depth).** Add `static_assert(max_slab_size_class <= UINT32_MAX, ...)` or, more precisely, an init-time check `assert(c->slab_size <= UINT32_MAX)` after `c->slab_size = get_slab_size(...)` (line 1321), to make the u32-division invariant explicit and fail loudly if geometry ever changes. The `slab_size` field is itself declared `u32` (line 278), which already enforces this at struct-store time; an assert would document *why*.

### CORE-05 — `get_free_slot` linear search has a tight but correct interaction with `get_mask` at the 64-bit boundary

- **Severity**: Informational
- **Type**: Verified-correct (no action)
- **Location**: `h_malloc.c:408-448` (`get_mask`, `get_free_slot`), `has_free_slots` at `:450-469`, `is_free_slab` at `:471-478`.

**Description.** I scrutinized the bitmap edge arithmetic for off-by-one because the masking of the final partial word is the classic place such bugs hide. `get_mask(slots)` returns `~0UL << slots` for `slots < 64` and `0` for `slots >= 64` (line 408-410). In the final word, valid slots are `[0, slots - i*64)`; the mask sets all *higher* bits so `ffz64` cannot select a non-existent slot. For `slots` an exact multiple of 64 (e.g., 64, 128), the trailing word is full and `get_mask(0) == ~0UL << 0`... — note `slots - i*U64_WIDTH` for the last word equals `U64_WIDTH` when `slots` is a multiple of 64, and `get_mask(64) == 0` (the `slots < U64_WIDTH` branch is false), meaning *no* artificial mask is applied, which is correct because that word is fully populated with real slots. The loop bound `(slots - 1) / U64_WIDTH` correctly identifies the last word index for both exact-multiple and non-multiple cases (e.g., `slots == 85` → words 0 and 1, last index 1; `slots == 64` → word 0 only). `has_free_slots` and `is_free_slab` use the same masking discipline (or the `SLAB_METADATA_COUNT` fast counter path), and `SLAB_METADATA_COUNT` is defined (line 115), so the production path uses `count` comparisons that cannot index out of range at all.

**Security Impact.** None — verified correct. `set_used_slot`/`clear_used_slot`/`is_used_slot` index `bitmap[index / 64]` with `index < slots <= 256`, so `bucket ∈ [0,3]`, always in-bounds for the 4-word array. The randomized variant (`SLOT_RANDOMIZE`) seeds the search at a random word and wraps via `i = i == (slots-1)/64 ? 0 : i+1`, never reading past the last populated word.

**Recommendation.** None.

### CORE-06 — Per-class `rng` is protected only by the size-class lock (correct, but worth stating)

- **Severity**: Informational
- **Type**: Verified-correct concurrency note
- **Location**: `random.h` (no internal lock), uses at `h_malloc.c:649,687,714,733` (alloc) and `:784,863,865` (free/enqueue), `post_fork_child` at `:1220-1233`.

**Description.** `struct random_state` carries no internal mutex; `get_random_*` are not individually synchronized. Every call site passes `&c->rng` (the per-size-class state) and every such call occurs while `c->lock` is held — the four `get_free_slot`/allocation call sites are inside `allocate_small` after `mutex_lock(&c->lock)` (line 635), and the quarantine/`enqueue_free_slab` call sites are inside `deallocate_small` after `mutex_lock(&c->lock)` (line 817). The region allocator likewise uses `&ra->rng` under `ra->lock`. There is no shared/global RNG on the slab hot path. After `fork`, `post_fork_child` re-initializes each `c->rng` (line 1229) so the child does not replay the parent's slot-selection / quarantine-displacement stream.

**Security Impact.** None — no data race exists and the post-fork reseed prevents cross-process predictability of slot randomization and quarantine displacement. Had the rng been shared without locking it could have produced biased/duplicate "random" indices, but that is not the case here.

**Recommendation.** None.

## Verified Strengths

The following claimed properties were checked against the code and **confirmed to hold**, with evidence:

- **Fully out-of-line metadata, no inline references.** `struct slab_metadata` lives in `slab_info_mapping` (`h_malloc.c:1000-1012`), a separate page-aligned region reached only by index arithmetic (`get_slab` line 328-331, `get_metadata` line 480-488). Nothing in the per-slot user region stores metadata pointers, sizes, or list links. The slab region base and class regions are reached only through the post-init read-only `ro` struct (`memory_protect_ro`, line 1332). **Confirmed.**

- **No deterministic / low-entropy offset to metadata.** The metadata mapping is a distinct `mmap` placed by the allocator's own `allocate_pages` with a random `metadata_guard_size` (line 1270-1274); the *slabs* additionally start at a per-class random `gap` (line 1310-1312) within their class region. There is no fixed delta between a user allocation and its metadata. **Confirmed.**

- **Dedicated free bit and separate quarantine bit per slot.** `u64 bitmap[4]` and `u64 quarantine_bitmap[4]` (line 118, 128) give one bit per slot up to 256 slots; `set/clear/is_used_slot` and `set/clear/is_quarantine_slot` (line 370-405) operate on the correct word/bit. **Confirmed.**

- **Deterministic rejection of unaligned / mid-slot frees, before any metadata write.** In `deallocate_small`, after deriving `slot` via u32 division, `slot_pointer(size, slab, slot) != p` aborts with `fatal_error("invalid unaligned free")` (line 825-827) *before* any canary check, zeroing, or bitmap mutation. An interior/unaligned pointer reconstructs to a different slot start and is rejected. **Confirmed.**

- **Deterministic double-free detection.** `is_used_slot` (line 829-831) catches frees of currently-free slots; with quarantine, `is_quarantine_slot` (line 851-853) catches re-frees of resident quarantined slots. Both run under the lock before any state change. **Confirmed** (see CORE-02 for the resident-vs-evicted nuance, which still results in deterministic detection via the `is_used_slot` guard).

- **Rejection of frees into unused / guard / gap regions.** A pointer below `class_region_start` (in the random gap) underflows `offset` and yields `index >= metadata_allocated` → `fatal_error("invalid free within a slab yet to be used")` (line 484-486). Pointers into not-yet-used slots or guard slabs have all-zero bitmaps → `is_used_slot` false → deterministic abort, and the underlying pages are `PROT_NONE` (`memory.c:30,49`). **Confirmed.**

- **Slot-index derivation cannot be abused to write attacker-chosen metadata.** The two-stage derivation (u64 region-offset division bounded by `metadata_allocated`, then u32 in-slab-offset division validated by `slot_pointer`) means the only metadata entry a freed pointer can touch is the one geometrically containing it, and only if it passes the alignment + `is_used_slot` + quarantine gates first. **Confirmed.**

- **Correct partial/empty/free list transitions; no double-counting.** Allocation pops from `partial_slabs` and unlinks a slab from `partial_slabs` only when it becomes full (`!has_free_slots`, line 736-741); deallocation re-inserts a now-not-full slab into `partial_slabs` (line 904-912) and, when it becomes fully free (`is_free_slab`, line 916), unlinks it from `partial_slabs` and pushes it onto `empty_slabs` (or purges to `free_slabs` past `max_empty_slabs_total`). I traced the `prev`/`next` updates for the doubly-linked `partial_slabs` and the singly-linked `empty_slabs`/`free_slabs` and found them consistent: a slab is on exactly one list at a time, and `empty_slabs_total` is incremented/decremented in lockstep with insert/remove (line 641, 948). The `slots == 1` corner case (where a slab is full immediately on its single allocation) is handled by the `slots > 1 ? metadata : NULL` assignments (line 646, 685, 712) and the "triggered even for slots == 1 and then undone below" comment path (line 903-914). **Confirmed.**

- **All shared slab state is lock-protected; no unlocked metadata reads on the small path.** Every bitmap/list/`rng`/quarantine access in `allocate_small`, `deallocate_small`, `memory_corruption_check_small`, and `h_malloc_object_size` is inside the `c->lock` critical section. The only lock-free reads are of the immutable, post-init read-only `ro` fields and `get_slab_region_end()` which uses an acquire-load against the release-store in init (line 88, 1330). **Confirmed — no TOCTOU between checking and mutating the slot bitmaps was found.**

- **Fork safety.** `full_lock`/`full_unlock` acquire/release the region lock and every size-class lock around `fork` (line 1198-1218), and `post_fork_child` re-inits every lock and reseeds every rng (line 1220-1233). This prevents a child from inheriting a locked mutex or a duplicated RNG stream. **Confirmed.**

## Claims Assessment

- **"Deterministic detection of any invalid free (unallocated, unaligned, etc.)"** — **Holds-with-caveats.** For the actual free paths (`h_free`, `h_free_sized`, `h_free_sized_aligned`, realloc slow path) it holds deterministically (alignment, `is_used_slot`, quarantine, and bounds checks, `h_malloc.c:821-853`). Caveat: the `realloc` *same-size identity* fast path (CORE-01, line 1569-1573) returns the pointer without these checks. It is not a free per se and performs no mutation, but it is the one small-allocator entry point that trusts an address-derived size class without a metadata probe.

- **"Fully out-of-line metadata; no references to metadata within the slab allocation region"** — **Holds.** Metadata is in a separate mapping reached only by index (`h_malloc.c:328-331,480-488,1000-1012`); no inline metadata exists.

- **"No deterministic/low entropy offsets to metadata"** — **Holds.** Random metadata guard size (line 1270) and random per-class slab gap (line 1310-1312); no fixed user→metadata delta.

- **"Dedicated free bit per slot plus separate quarantine bitmap"** — **Holds.** `bitmap[4]` and `quarantine_bitmap[4]`, one bit per slot (line 118, 128, 370-405).

- **"Proper double-free detection for quarantined allocations"** — **Holds.** Resident re-frees caught by `is_quarantine_slot` (line 851); evicted re-frees caught by `is_used_slot` (line 829). Detection is deterministic in both states (CORE-02).

- **"Slot index validation cannot be abused (unaligned, guard slabs, mid-slot)"** — **Holds.** Two-stage bounded division plus `slot_pointer(...) == p` reconstruction (line 821-827) and `is_used_slot` (line 829); guard/gap/unused regions are `PROT_NONE` and have zero bitmaps.

- **Integer/pointer arithmetic soundness (truncation/overflow)** — **Holds.** u64 divisor for the up-to-32 GiB region offset, u32 divisor for the bounded (<131072 B) in-slab offset; no truncation reachable (CORE-04 notes the implicit invariant and recommends an explicit assert).

- **Concurrency: all shared slab state under the size-class lock; no TOCTOU on bitmaps** — **Holds.** Verified every mutable access is inside `c->lock`; immutable state is read-only post-init (line 1332).

- **Fork safety of slab state** — **Holds.** `pthread_atfork` handlers lock/reinit all locks and reseed RNGs (line 1198-1233, 1340).

---

### Summary of Findings

| ID | Severity | Type | Title |
|----|----------|------|-------|
| CORE-01 | Low | Design-limitation | `realloc` same-size fast path skips slot/quarantine/canary validation |
| CORE-02 | Informational | Design-limitation | Quarantine double-free diagnostic is exhaustive only for resident entries (by design) |
| CORE-03 | Informational | Design observation | `get_metadata` bounds check uses `metadata_allocated`; residual gap covered by PROT_NONE + zero bitmap |
| CORE-04 | Informational | Design observation | In-slab offset truncated to u32 for slot division; safe given slab-size bounds — add explicit assert |
| CORE-05 | Informational | Verified-correct | `get_free_slot`/`get_mask` 64-bit boundary masking is correct (no off-by-one) |
| CORE-06 | Informational | Verified-correct | Per-class `rng` correctly protected by the size-class lock; reseeded post-fork |

**Verdict:** The core slab allocator is robust. No memory-safety vulnerabilities were found; invalid-free and double-free detection are deterministic and correctly ordered ahead of any metadata mutation, the arithmetic is correctly sized, and all shared state is properly synchronized. The single actionable item (CORE-01, Low) is a missed *detection* opportunity in `realloc`'s same-size fast path with no corruption potential; the remainder are informational confirmations and minor defense-in-depth suggestions.
