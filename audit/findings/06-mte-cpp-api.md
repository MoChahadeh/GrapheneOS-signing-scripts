# Memory Tagging (MTE), C++ Allocator & API Surface — Audit Findings

Audit target: GrapheneOS `hardened_malloc` @ commit `9e88c14`
Subsystem: ARM MTE support, C++ `operator new`/`delete`, integer-overflow handling across the public API, and API-surface correctness (alignment, sized free, `usable_size`/`object_size`).
Files reviewed: `arm_mte.h`, `memtag.h`, `memory.c`, `memory.h`, `new.cc`, `include/h_malloc.h`, `util.h`, `pages.h`, and the relevant sections of `h_malloc.c`, plus `config/default.mk`, `config/light.mk`, `androidtest/memtag/memtag_test.cc`, and the README "Memory tagging" section.

---

## Subsystem Overview

**MTE.** When built with `-DHAS_ARM_MTE` (set by the downstream Android/GrapheneOS build; not defined in the in-tree `Makefile`), `memtag.h` defines `MEMTAG`, `RESERVED_TAG 0`, and `TAG_WIDTH 4`. The slab region is mapped `PROT_MTE` via `memory_map_tagged()`/`memory_map_fixed_tagged()` (`h_malloc.c:97-113`), gated on a runtime flag `ro.is_memtag_disabled` (`h_malloc.c:80-94`) that Android can flip via `h_malloc_disable_memory_tagging()` (`h_malloc.c:2268-2298`). Each slab allocation is tagged with a random tag (hardware `IRG` instruction, `arm_mte.h:9-11`) and zeroed in the same pass (`STZG`/`DC GZVA`, `arm_mte.h:26-90`) by `tag_and_clear_slab_slot()` (`h_malloc.c:596-624`). On free, the slot is retagged with the reserved tag 0 and zeroed (`h_malloc.c:838-842`). Per-slot "most recent tag" history is kept in `metadata->arm_mte_tags[]` (`h_malloc.c:130-141`) and used to build a 4-value tag-exclusion mask. When MTE is enabled, the write-after-free scan and canary read/write are disabled (`h_malloc.c:500-503,537-539,549-552`).

**C++ allocator.** `new.cc` (155 lines) forwards all `operator new` variants to `h_malloc`/`h_aligned_alloc` with a conforming `std::new_handler` retry loop and `std::__throw_bad_alloc()` on failure; `nothrow` variants suppress the throw. `delete` forwards to `h_free`; **sized** `delete` forwards to `h_free_sized`/`h_free_aligned_sized`, turning C++14 sized deallocation into a security check rather than an optimization.

**Integer overflow / API.** `h_calloc` uses `__builtin_mul_overflow` (`h_malloc.c:1533`). Alignment APIs funnel through `allocate_aligned()` (`h_malloc.c:1445`) which validates power-of-two and `>= min_alignment`. `adjust_size_for_canary()` (`h_malloc.c:1492`) only adds the canary inside the slab size range, avoiding overflow. `usable_size`/`object_size` return rounded class sizes minus the canary, never raw metadata.

---

## Findings

### MTE-01 — MTE tag-selection algorithm is correct, including slab-edge slots (no OOB, no infinite loop)
- **Severity:** Informational (verified-correct)
- **Type:** Verified strength (not a bug)
- **Location:** `h_malloc.c:596-624`, array declared `h_malloc.c:130-141`, helpers `util.h:72-83`
- **Description:** I scrutinized this for an off-by-one or OOB metadata read at the first/last slot, and the construction is sound. `arm_mte_tags` is a `u8[129]` viewed as 258 4-bit entries (indices 0..257). The per-slot tag is stored *shifted right by one*: slot `i`'s tag lives at nibble `i+1`. The exclusion mask reads nibble `i` (left neighbor `i-1`), `i+1` (this slot's previous tag), and `i+2` (right neighbor `i+1`) (`h_malloc.c:610-614`). Maximum `slot_idx` is 255 (size class 0 and the 16-byte class have 256 slots — `h_malloc.c:181-182`), so the highest index touched is `255+2 = 257`, exactly the last valid nibble. The first/last *real* slots read sentinel nibbles 0 and 257 which are never written (the lowest written nibble is index 1) and so are permanently 0, contributing only the already-set `RESERVED_TAG` bit. This is why the comment at `h_malloc.c:601-603` says edge slots are handled "branchless"; the claim checks out and there is **no out-of-bounds metadata access**.
- The "increment past matching values" is the hardware `IRG` semantics driven by the exclusion mask, not a software loop, so termination is not a concern. The mask excludes at most 4 *distinct* tag values out of 16, leaving ≥12 candidates; `IRG` cannot fail to produce an allowed tag.
- **Security Impact:** None — this confirms deterministic linear-overflow detection (distinct tags vs. both neighbors) and one-cycle deterministic UAF detection (distinct from the slot's own previous tag) as claimed. `androidtest/memtag/memtag_test.cc:47-189` independently asserts these distinctness properties across all listed size classes.
- **Recommendation:** None. Consider promoting the `MAX_SLAB_SLOT_COUNT`/array-size relationship from a comment to a `static_assert` (see DiD-01) so a future bump of `size_class_slots[]` above 256 can't silently overflow `arm_mte_tags`.

### MTE-02 — Free-time tag history is intentionally *not* reset; this is required for correctness, not a bug
- **Severity:** Informational (verified-correct)
- **Type:** Verified strength (design subtlety worth recording)
- **Location:** `h_malloc.c:838-842` (free) vs. `h_malloc.c:620-621` (allocate)
- **Description:** On free, the slot's memory is retagged to `RESERVED_TAG` (0) and zeroed, but `metadata->arm_mte_tags[slot+1]` is deliberately left holding the *allocation* tag (comment at line 840). I verified this is necessary: on the next reuse, `tag_and_clear_slab_slot` reads that stored value as "previous tag of this slot" and excludes it (`h_malloc.c:611-612`), guaranteeing the reused slot gets a tag different from its last live tag. Had free zeroed the history, the exclusion would collapse to `RESERVED_TAG` only and the slot could legitimately receive its prior tag again, defeating the "previous tag for the slot" property and the deterministic single-cycle UAF guarantee.
- **Security Impact:** None; this preserves the claimed UAF property. Worth flagging because it looks like a missing update on first read.
- **Recommendation:** None.

### MTE-03 — Runtime MTE-disable path leaves canaries permanently inert for already-initialized slabs (documented tradeoff)
- **Severity:** Low
- **Type:** Design limitation (explicitly documented)
- **Location:** `h_malloc.c:514-567` (canary set/check gating), `h_malloc.c:2268-2298` (`h_malloc_disable_memory_tagging`), README "Memory tagging" final paragraph
- **Description:** Android can disable MTE at any time. While MTE is enabled, `set_canary`/`check_canary` early-return (`h_malloc.c:537-539,549-552`) so canary bytes are never written — they remain whatever `arm_mte_tag_and_clear_mem` left them (zero). `set_slab_canary_value` still computes a non-zero `canary_value` per slab and forces it to `0x100` if the RNG yields 0 (`h_malloc.c:520-529`). After MTE is turned off at runtime, newly *handed-out* slots from slabs whose canary region is still zero will be checked with `check_canary`, which explicitly treats a stored canary of `0` as "skip" (`h_malloc.c:557-561`). Net effect: for the window/slabs that were touched under MTE, canary-based overflow detection stays off even after MTE is disabled. This is the behavior the README calls out ("Canaries will be more thoroughly disabled when using memory tagging in the future…").
- **Security Impact:** A real but bounded reduction in defense-in-depth: after a dynamic MTE→off transition, some slab allocations have neither MTE nor a working canary until their slab is recycled and re-canaried. There is no memory-safety *regression* versus a build with canaries disabled, and no double-free/zeroing inconsistency was found — the `skip_zero` flag and `ZERO_ON_FREE` remain coherent because zeroing still happens via either the MTE store-zero path (when on) or `memset` (when off) (`h_malloc.c:836-847`).
- **Recommendation:** None required; behavior matches the documented tradeoff. If stronger post-disable canary coverage is ever wanted, re-arming canaries on slab recycle after a disable event would close the window. Note that the `canary_value == 0` skip in `check_canary` is load-bearing for this design and should be retained.

### MTE-04 — `h_malloc_disable_memory_tagging` flips the switch but does not (and cannot) re-protect already-PROT_MTE slab memory; tag checks on existing allocations effectively stop
- **Severity:** Informational
- **Type:** Design limitation (inherent to MTE/`PROT_MTE` + Android model)
- **Location:** `h_malloc.c:2268-2298`, `memory.c:33-58` (note: "PROT_MTE can't be cleared via mprotect")
- **Description:** Disabling sets `ro.is_memtag_disabled = true` under `full_lock()` with a correct unprotect/reprotect of the read-only `ro` page (`h_malloc.c:2279-2285`). New mappings then use plain `memory_map`/`memory_map_fixed`. Existing slab regions remain `PROT_MTE` (it cannot be cleared), but tag *checking* is governed by the process-wide MTE mode that the caller (bionic) is changing in tandem; hardened_malloc just stops generating tagged pointers. There is no half-on allocator state: allocate/free both consult `is_memtag_enabled()` at each step (`h_malloc.c:656,693,720,749,838`), so a free performed after disable will `memset`-zero rather than tag-zero, and an allocate after disable returns an untagged pointer with a written canary.
- **Security Impact:** None beyond MTE-03. The switch is consistent; I found no path where tagging is half-enabled such that a slot is handed out with a stale or duplicate tag.
- **Recommendation:** None.

### CPP-01 — Sized `operator delete` enforces size/alignment match (type-confusion detection) — works, with a benign caveat for over-aligned types
- **Severity:** Informational (verified-correct, minor caveat)
- **Type:** Verified strength
- **Location:** `new.cc:77-83,149-155`; enforcement in `h_free_sized` (`h_malloc.c:1746-1772`), `h_free_aligned_sized` (`h_malloc.c:1774-1809`), `deallocate_small` (`h_malloc.c:811-813`), `deallocate_large` (`h_malloc.c:1433-1436`)
- **Description:** Plain sized `delete(void*, size_t)` calls `h_free_sized`, which rounds `expected_size` through `adjust_size_for_canary` + `get_size_info` and aborts via `fatal_error("sized deallocation mismatch …")` on any mismatch with the allocation's recorded class size — deterministically, not silently. This implements the claimed "validation of the size passed for C++14 sized deallocation … even for code compiled with earlier standards." For large allocations it compares against `get_large_size_class(*expected_size)` against the exact region size. I checked for false positives: because both the allocation and the sized-free path normalize through the *same* `get_size_info`/`get_large_size_class` rounding, any `size` the compiler legitimately passes for a given object maps to the same class, so legitimate deletes don't trip the check.
- **Caveat:** For an over-aligned type allocated via aligned `new`, the compiler emits the **aligned** sized delete `delete(void*, size_t, align_val_t)` → `h_free_aligned_sized`, which re-derives the class with `get_size_info_align(expected_size, alignment)` (`h_malloc.c:1792-1796`). This matches the aligned-allocation rounding (`allocate_aligned` → `get_size_info_align`, `h_malloc.c:1451-1452`), so it is consistent. A mismatch only occurs under genuine type confusion or a wrong explicit alignment, which is the intended detection.
- **Security Impact:** Positive — converts a UB performance hook into a corruption/type-confusion tripwire.
- **Recommendation:** None.

### CPP-02 — `operator delete` nullptr handling is correct
- **Severity:** Informational
- **Type:** Verified strength
- **Location:** `new.cc:61-83,133-155`; `h_free` (`h_malloc.c:1721-1724`), `h_free_sized` (`h_malloc.c:1746-1749`), `h_free_aligned_sized` (`h_malloc.c:1774-1777`)
- **Description:** All `delete`/sized-`delete`/aligned-`delete` variants reach a `h_free*` that returns immediately on `ptr == NULL`. `delete nullptr` and sized `delete nullptr` are no-ops as required by the standard, with no metadata lookups on the null path.
- **Security Impact:** None (correct).
- **Recommendation:** None.

### CPP-03 — `new`/`new[]` out-of-memory handling is standard-conforming; `nothrow` cannot leak a C++ exception
- **Severity:** Informational
- **Type:** Verified strength
- **Location:** `new.cc:13-43,85-115`
- **Description:** On allocation failure, `handle_out_of_memory` runs the installed `std::new_handler` in a loop, breaking if the handler is null or itself throws `std::bad_alloc` (caught), then throwing `std::bad_alloc` only in the throwing variants. The `nothrow` variants are `noexcept` and return `nullptr` without throwing, matching `[new.delete.single]`. The aligned overload mirrors this via `h_aligned_alloc`.
- **Security Impact:** None; avoids `terminate()` surprises and respects custom OOM handlers.
- **Recommendation:** None. (Minor portability note, not a vuln: `std::__throw_bad_alloc` and the `<bits/…>` includes are libstdc++/libc++ internals; the `__has_include` guards at `new.cc:1-6` handle this and `CONFIG_CXX_ALLOCATOR` is the opt-in.)

### API-01 — `malloc_usable_size` / `malloc_object_size` are not a metadata-leak oracle, but `usable_size` is a (by-design) size-class rounding oracle
- **Severity:** Low
- **Type:** Design limitation (inherent to the API contract)
- **Location:** `h_malloc_usable_size` (`h_malloc.c:1846-1876`), `h_malloc_object_size` (`h_malloc.c:1878-1940`), `h_malloc_object_size_fast` (`h_malloc.c:1942-1960`), `slab_usable_size` (`h_malloc.c:775-777`)
- **Description:** All three return the **size-class** value (or large-region size) minus `canary_size`, never raw pointers, canary bytes, tags, slot indices, or guard sizes. `usable_size` and `object_size` additionally run full corruption checks first (`memory_corruption_check_small`, used-slot/quarantine checks, canary check), aborting on a bad pointer rather than returning attacker-useful state. So they are **not** an oracle for allocator metadata, slot geometry, or the canary value. They *do* reveal the rounded size class (e.g., a 17-byte request reports 32), which is inherent to any `malloc_usable_size` and leaks at most ~log2 bits of the requested size — information an attacker who controls the allocation already knows. `object_size` correctly bounds an interior pointer to `usable - offset` and aborts if `offset > usable` (`h_malloc.c:1919-1921`).
- **Security Impact:** Negligible; consistent with the documented contract ("upper bound on object size … based on malloc metadata"). No entropy (canary/tag/guard) is exposed.
- **Recommendation:** None. (Defense-in-depth: callers must not treat `usable_size` as the allocation size for bounds — but that is a universal `malloc` caveat, not a hardened_malloc issue.)

### API-02 — `free_sized` / `free_aligned_sized` reject wrong size/alignment deterministically
- **Severity:** Informational
- **Type:** Verified strength
- **Location:** `h_malloc.c:1746-1809`
- **Description:** `h_free_sized` aborts if the (canary-adjusted) expected size exceeds `max_slab_size_class` while the pointer is in the slab region (`h_malloc.c:1756-1758`) and otherwise passes `&expected_size` down so `deallocate_small`/`deallocate_large` abort on class mismatch. `h_free_aligned_sized` additionally validates the alignment is a power of two and `<= PAGE_SIZE` for slab pointers (`h_malloc.c:1784-1786`) before deriving the class. All rejections are `fatal_error`, i.e. deterministic, never silent acceptance. The zero-size class is special-cased correctly (`deallocate_small` compares against 0 for class 0, `h_malloc.c:810-812`).
- **Security Impact:** Positive — these are hardening checks, not just optimizations.
- **Recommendation:** None.

### API-03 — `h_calloc` multiply-overflow is safe; large-size canary/page rounding overflows are handled
- **Severity:** Informational
- **Type:** Verified strength
- **Location:** `h_calloc` (`h_malloc.c:1531-1548`), `adjust_size_for_canary` (`h_malloc.c:1492-1497`), `get_large_size_class`/`page_align` (`h_malloc.c:1367-1381`, `pages.h:19-21`)
- **Description:** `h_calloc` computes `nmemb*size` with `__builtin_mul_overflow` and returns `ENOMEM` on overflow before any allocation (`h_malloc.c:1533-1536`). I traced the largest-input edges for the rest:
  - `adjust_size_for_canary` only adds `canary_size` when `0 < size <= max_slab_size_class`, so it can never overflow (`h_malloc.c:1493-1494`); for huge sizes it returns the value unchanged and the request is routed to `allocate_large`.
  - `page_align(size)` overflows to a small value/0 for `size > SIZE_MAX - PAGE_SIZE + 1`, but every caller that can receive an attacker-large size funnels through `get_large_size_class`, which is documented "Returns 0 on overflow" and whose callers (`allocate_large` `h_malloc.c:1388-1392`, `allocate_aligned` `h_malloc.c:1463-1466`, `h_realloc` `h_malloc.c:1557-1561`) check for 0 and return `ENOMEM`/`NULL`. With `CONFIG_LARGE_SIZE_CLASSES` (the default), `get_large_size_class` routes through `get_size_info`, which for an over-large `size` produces an enormous class that `allocate_pages` fails to map → graceful `NULL`.
  - `h_pvalloc` calls `page_align(size)` and checks for the 0 result (`h_malloc.c:1711-1715`) before allocating, so a page-rounding overflow is caught.
  - `h_realloc` applies `adjust_size_for_canary` before the `> max_slab_size_class` branch (`h_malloc.c:1551-1562`); since the canary addition is suppressed above the slab range, there is no pre-check overflow.
- **Security Impact:** None; the overflow surface is closed by explicit checks and `__builtin_mul_overflow`.
- **Recommendation:** None.

### API-04 — Alignment validation in `allocate_aligned`/`posix_memalign`/`aligned_alloc` is correct
- **Severity:** Informational
- **Type:** Verified strength
- **Location:** `allocate_aligned` (`h_malloc.c:1445-1448`), `h_posix_memalign` (`h_malloc.c:1695-1697`), `h_aligned_alloc`/`h_memalign` (`h_malloc.c:1699-1703`), `h_valloc`/`h_pvalloc` (`h_malloc.c:1705-1718`)
- **Description:** `allocate_aligned` rejects non-power-of-two (`(alignment-1) & alignment`) and `alignment < min_alignment` with `EINVAL` (`h_malloc.c:1446`). `h_posix_memalign` passes `min_alignment = sizeof(void*)`; since any power of two ≥ `sizeof(void*)` is automatically a multiple of `sizeof(void*)`, the POSIX "multiple of sizeof(void*)" requirement is satisfied transitively. `aligned_alloc`/`memalign`/`valloc`/`pvalloc` pass `min_alignment = 1` (C/historical semantics), still requiring power-of-two. `alignment == 0` is rejected because `(0-1)&0 == 0` is false only when… — concretely `alignment=0`: `(alignment-1)&alignment = (SIZE_MAX)&0 = 0` → not rejected by the power-of-two test, **but** `alignment < min_alignment` catches `0 < sizeof(void*)` for `posix_memalign`; for `aligned_alloc` (`min_alignment=1`) `0 < 1` is true so `0` is rejected there too. Good — zero alignment is rejected on every entry point.
- **Security Impact:** None; invalid alignments cannot reach the allocator core.
- **Recommendation:** None.

### DiD-01 — Add a `static_assert` binding `MAX_SLAB_SLOT_COUNT` to the `arm_mte_tags[]` size
- **Severity:** Low
- **Type:** Defense-in-depth
- **Location:** `h_malloc.c:130-141` (array), `h_malloc.c:180-195` (`size_class_slots`), `h_malloc.c:596-624` (consumer)
- **Description:** The invariant "max slot count ≤ 256, hence `arm_mte_tags` needs `(256+2)/2 = 129` bytes and `slot_idx+2 ≤ 257`" lives only in comments. If a future config raises any `size_class_slots[]` entry above 256, `tag_and_clear_slab_slot` would read/write `arm_mte_tags` out of bounds (a metadata corruption primitive) with no compile-time guard. There is no `MAX_SLAB_SLOT_COUNT` macro to anchor a check today.
- **Security Impact:** None at present (max is 256); purely a future-proofing measure for a security-critical bound.
- **Recommendation:** Introduce `#define MAX_SLAB_SLOT_COUNT 256`, derive the array size from it, and add `static_assert(sizeof(((struct slab_metadata*)0)->arm_mte_tags) * 2 >= MAX_SLAB_SLOT_COUNT + 2, …)` plus a `static_assert` that every `size_class_slots[i] <= MAX_SLAB_SLOT_COUNT` (e.g. validated in a small loop or against the known maximum).

### DiD-02 — Consider documenting that `usable_size` rounds (oracle) directly in the public header
- **Severity:** Informational
- **Type:** Defense-in-depth (doc)
- **Location:** `include/h_malloc.h:69`, `h_malloc.c:1846-1876`
- **Description:** `h_malloc_object_size` is documented as returning an "upper bound", but `h_malloc_usable_size` (the glibc-compatible symbol) has no comment that it returns a rounded size-class value. Not a vulnerability; a note discourages callers from inferring exact request sizes or using the value as a security boundary.
- **Recommendation:** Add a one-line comment; no code change.

---

## Verified Strengths

- **MTE tag algebra is correct and OOB-safe at slab edges** via the shift-by-one sentinel scheme (`h_malloc.c:596-624,130-141`), independently checked by `androidtest/memtag/memtag_test.cc:47-189`. All four exclusion categories (reserved 0, this-slot-previous, left neighbor, right neighbor) are applied; `IRG` always has ≥12 candidate tags.
- **Reserved tag 0 is never handed out:** it is always present in the exclusion mask (`h_malloc.c:607`), and bionic additionally reserves it via `PR_MTE_TAG_MASK` (`memtag.h:9`). Untagged pointers therefore cannot access slab allocations (claim holds).
- **Free sets the reserved tag and zeroes in one pass** (`h_malloc.c:838-842` via `arm_mte_tag_and_clear_mem`), giving deterministic use-after-free detection; slot history retention (`h_malloc.c:840`) preserves single-cycle UAF distinctness.
- **MTE/canary/WAF switch is consistent** — every allocate and free path consults `is_memtag_enabled()` (`h_malloc.c:500,537,549,656,693,720,749,838`); no half-on state, no double-free or skipped-zeroing path (`skip_zero` is coherent with `ZERO_ON_FREE`, and `static_assert(ZERO_ON_FREE,…)` in `h_calloc` `h_malloc.c:1545` enforces the invariant under MTE).
- **C++ sized delete is a real type-confusion tripwire** (`new.cc:77-83,149-155` → deterministic `fatal_error`), conforming new-handler/`bad_alloc` semantics (`new.cc:13-43,85-115`), correct nullptr handling (`new.cc:61-83`).
- **`__builtin_mul_overflow` for calloc** (`h_malloc.c:1533`) and **overflow-safe size rounding** (`adjust_size_for_canary` cannot overflow; `get_large_size_class` returns 0 on overflow and all callers check).
- **Alignment validation** rejects non-power-of-two and zero on every public entry point (`h_malloc.c:1446`, with `min_alignment` differentiating POSIX vs C semantics).
- **`usable_size`/`object_size` are not a metadata oracle:** rounded sizes only, canary subtracted, full corruption checks before returning, interior-pointer bound enforced (`h_malloc.c:1846-1960`).
- **`PROT_MTE` immutability respected:** code comments and logic acknowledge `PROT_MTE` can't be cleared by `mprotect` (`memory.c:34,54`), and the disable path relies on the process MTE mode rather than attempting an impossible unmap-clear.

---

## Claims Assessment

| Claim | Verdict | Justification |
|---|---|---|
| "Random memory tags as the baseline" for slab allocations | **Holds** | `tag_and_clear_slab_slot` uses hardware `IRG` random tag for every requested-size slab slot (`h_malloc.c:616`, called at `h_malloc.c:657,694,721,750`). |
| "Dedicated tag for free slots, set on free, for deterministic protection against accessing freed memory" | **Holds** | Free retags slot to `RESERVED_TAG` and zeroes (`h_malloc.c:838-842`); any tagged access to the freed slot mismatches deterministically. |
| "Guarantee distinct tags for adjacent allocations by incrementing past matching values (deterministic linear-overflow detection)" | **Holds** | Left/right neighbor tags are excluded via the mask (`h_malloc.c:610,614`); `IRG` cannot return an excluded value. Test asserts adjacency distinctness (`memtag_test.cc:113-123`). |
| Exclude 4 values: tag 0, previous tag for the slot, current/previous tags of left and right neighbors | **Holds** | Exactly four `tem |=` terms (`h_malloc.c:607,610,612,614`); edge neighbors read permanent-0 sentinels (MTE-01). |
| "Reserved 0 tag … untagged pointers can't access slab allocations and vice versa" | **Holds** | `RESERVED_TAG` always excluded (`h_malloc.c:607`) and reserved by bionic (`memtag.h:9`); free-tag is 0 so untagged access to live slots also mismatches. |
| Slab slots cleared before reuse under MTE | **Holds** | `arm_mte_tag_and_clear_mem` zeroes during tagging (`arm_mte.h:26-90`); test asserts zeroing (`memtag_test.cc:135-140`). |
| "When memory tagging is enabled, write-after-free check and canary checks are both disabled" | **Holds** | `write_after_free_check` (`h_malloc.c:500-503`), `set_canary`/`check_canary` (`h_malloc.c:537-539,549-552`) early-return under MTE. |
| Sized-deallocation size validation detects type confusion even pre-C++14 | **Holds** | `h_free_sized`/`h_free_aligned_sized` + `deallocate_*` abort on size/alignment mismatch (`h_malloc.c:811-813,1433-1436,1756-1796`); wired from `new.cc:77-83,149-155`. |
| calloc overflow safety | **Holds** | `__builtin_mul_overflow` guard (`h_malloc.c:1533-1536`). |
| Alignment APIs reject invalid alignments | **Holds** | Power-of-two + min-alignment + zero rejection on all entry points (`h_malloc.c:1446`, API-04). |
| Canaries "more thoroughly disabled in the future" under dynamic MTE (current limitation) | **Holds-with-caveats** | Confirmed: after a runtime MTE→off transition, slabs touched under MTE keep zeroed (inert) canaries until recycled (MTE-03). This is the stated, accepted tradeoff, not a regression. |
| MTE runtime disable is consistent (no stale/duplicate tag handout, no half-on state) | **Holds** | Single `is_memtag_disabled` flag under `full_lock` with `ro`-page reprotect (`h_malloc.c:2276-2287`); all alloc/free paths branch on it; `PROT_MTE` immutability acknowledged (MTE-04). |

**Overall:** The MTE implementation, the C++ allocator, and the integer-overflow/alignment/sized-free handling are **sound and match the documented claims**. No memory-safety vulnerabilities were found in this subsystem. The only substantive items are a documented dynamic-MTE/canary tradeoff (MTE-03/04) and a future-proofing `static_assert` for the tag-history array bound (DiD-01).
