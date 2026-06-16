# Canaries, Quarantine & Write-After-Free — Audit Findings

Audit target: GrapheneOS `hardened_malloc`, commit `9e88c14305440c45551789c284c1de08ec08e451`
Subsystem: small-allocation heap-hardening — slab canaries, zero-on-free, write-after-free (WAF) detection, slab quarantine (random array + FIFO queue), and the `light` configuration delta.
Scope: `h_malloc.c`, `util.h`, `config/default.mk`, `config/light.mk`, `random.{c,h}`, `README.md`.

---

## Subsystem Overview

For a non-zero small allocation of user-requested size `R`, the public entry points add the
canary up front: `adjust_size_for_canary()` (h_malloc.c:1492) bumps the request to `R + canary_size`
(`canary_size = 8` when `SLAB_CANARY`, else 0; h_malloc.c:56) *before* size-class selection. The
slot the user receives therefore has size-class size `S = c->size`, of which the trailing 8 bytes
are the canary and `S - 8` are usable. `malloc_usable_size` subtracts the canary back out
(h_malloc.c:1859).

Per-slab canary value: `set_slab_canary_value()` (h_malloc.c:514) draws `get_random_u64()` and masks
off the byte adjacent to user data (`canary_mask = 0xffffffffffffff00` on little-endian), giving a
56-bit random value with a guaranteed leading zero byte. It is generated **once per slab** when the
slab is first activated (free→partial transition; called at h_malloc.c:669, 710) and stored in
out-of-line metadata (`struct slab_metadata.canary_value`, h_malloc.c:122).

Placement/checking:
- `set_canary()` (h_malloc.c:534) writes the value to `[p + S - 8, p + S)` at allocation time.
- `check_canary()` (h_malloc.c:546) verifies it on free (h_malloc.c:834) and on
  `malloc_usable_size`/`memory_corruption_check_small` (h_malloc.c:1834). It is **not** checked on
  the allocation fast paths.

Zero-on-free + WAF: on `deallocate_small`, after the canary check, the slot's usable region is
`memset(p, 0, S - canary_size)` (h_malloc.c:846) when `ZERO_ON_FREE` and MTE is not active. On
allocation from a reused (empty/partial) slab, `write_after_free_check(p, S - canary_size)`
(h_malloc.c:653, 746) ORs together every 8-byte word of the usable region and aborts if any bit is
set (h_malloc.c:494-512).

Quarantine: when `SLAB_QUARANTINE`, a freed slot is marked in `quarantine_bitmap`
(`set_quarantine_slot`, h_malloc.c:392/855) and the pointer is pushed first through a per-size-class
random array (`quarantine_random`, h_malloc.c:867) and then through a FIFO queue
(`quarantine_queue`, h_malloc.c:882). Only the pointer *evicted* from the queue is actually returned
to the slab's free bitmap (`clear_used_slot`, h_malloc.c:914). Per-class lengths are scaled by
`quarantine_shift = clz64(size) - (63 - MAX_SLAB_SIZE_CLASS_SHIFT)` (h_malloc.c:857) so smaller
classes get proportionally longer quarantines (e.g. with extended size classes the base of `1`
becomes 8192 slots for the 16-byte class, down to 1 for the 128 KiB class).

`light` config: `ZERO_ON_FREE=true`, `SLAB_CANARY=true`, but `WRITE_AFTER_FREE_CHECK=false`,
`SLOT_RANDOMIZE=false`, and both quarantine lengths `=0` (`SLAB_QUARANTINE` compiles out entirely).

Overall this is a careful, internally-consistent implementation. The findings below are dominated by
**inherent/documented design tradeoffs** and **defense-in-depth** suggestions; I did **not** find a
memory-safety bug in the canary/zero/WAF/quarantine logic.

---

## Findings

### HARDEN-01 — Canary value is per-slab, not per-slot: one leaked canary unlocks every slot in the slab
**Severity:** Low–Medium (probabilistic mitigation weakening, not a memory-safety bug)
**Type:** Design-limitation (documented)
**Location:** h_malloc.c:122 (`canary_value` in slab metadata), 514-532 (`set_slab_canary_value`), 542 (`set_canary`)

**Description.** A single 56-bit random `canary_value` is generated per slab and written verbatim to
the tail of **every** slot in that slab (`set_canary` copies `metadata->canary_value`). The README
acknowledges this: "The other 7 bytes are a per-slab random value" (README.md:270-271). Consequently,
any primitive that discloses the 8 canary bytes of *one* live allocation (e.g. an adjacent
out-of-bounds read, an uninitialized-read of a neighbouring slot, or a info-leak that spans a slot
boundary) yields the canary that an attacker must replicate to defeat the free-time `check_canary`
for **all other slots in the same slab** (up to 256 slots for the 16-byte class; size_class_slots[],
h_malloc.c:180). A sequential/linear overflow that overwrites a neighbour's canary can then restore
the correct value and survive the free-time check.

**Security Impact.** Reduces the effective entropy a remote attacker faces from "56 bits per target
slot" to "56 bits per slab, once." For exploits that already have a same-slab read primitive, the
canary's free-time detection contributes ~0 additional bits. This is a deliberate
performance/locality tradeoff (per-slot random canaries would require per-slot storage or derivation
and a keyed PRF at alloc/free time), and the canary's *primary* role — absorbing small overflows as
padding — is unaffected. Classify as a real but **accepted** limitation.

**Recommendation.** Document the per-slab reuse explicitly in the "Security properties" bullet
(currently only "High entropy per-slab random values", README.md:461). For a defense-in-depth
upgrade, consider deriving a per-slot canary as `keyed_hash(slab_secret, slot_index)` (e.g. a cheap
SipHash/AES-round mix) so a single-slot leak does not generalize. This is a cost/benefit decision,
not a defect.

---

### HARDEN-02 — Overflow into size-class slack space is undetectable until free, and only at free (by design)
**Severity:** Low
**Type:** Design-limitation (explicitly documented tradeoff)
**Location:** h_malloc.c:1492-1497 (`adjust_size_for_canary`), 542 (canary at end of *size-class* slot), README.md:391-403

**Description.** The canary is placed at the very end of the **size-class** slot, not immediately
after the user's requested `R` bytes. For requests that round up (e.g. `malloc(130)` → class 160,
giving `160 - 8 = 152` usable bytes), there are up to ~`S - 8 - R` bytes of slack between the user's
intended end and the canary. A linear overflow confined to that slack region writes only into
still-usable bytes, never touches the canary, and is therefore **never detected** — not on free, not
on realloc, not on `malloc_usable_size`. The README states this is intentional (README.md:392-397:
"doesn't minimize slack space ... slack space is helpful rather than harmful despite not detecting
the corruption on free"), the rationale being that such writes are *contained* (harmless) precisely
because they cannot reach metadata or the next slot.

**Security Impact.** No spatial-safety violation results (the writes stay inside the victim's own
slot), but it means the canary is an *absorber*, not a *detector*, for the common rounded-size case.
Combined with HARDEN-03 (detection only on free), an attacker who overflows exactly into slack and
whose target is the *contents* of their own oversized slot (e.g. a co-located length field or
function pointer the application itself placed in the slack) gets no allocator-level signal. This is
inherent to size-class allocators and is a reasonable tradeoff.

**Recommendation.** None required; behaviour matches documentation. If a deployment wanted
detection-over-absorption it would need right-justified placement or precise canaries, which the
project explicitly rejects for performance. Keep as documented limitation.

---

### HARDEN-03 — Canary integrity is verified only on free / size-query, never on the allocation fast path
**Severity:** Low
**Type:** Design-limitation (documented)
**Location:** h_malloc.c:834 (free), 1834 (`malloc_usable_size`); allocation paths h_malloc.c:652-660, 690-697, 717-724, 745-753 call `set_canary` but never `check_canary`.

**Description.** On the allocation paths the code (re)writes the canary (`set_canary`) but does not
read-and-verify the previously-present canary. Verification happens only when the slot is freed
(h_malloc.c:834) or queried via `malloc_usable_size`/`malloc_object_size` (h_malloc.c:1834). For a
long-lived allocation that is overflowed-into-its-neighbour and never freed (or freed only at
process teardown), the corruption of the *neighbour's* canary is detected only when that neighbour
is itself freed. The README concedes this directly: "checking on free will often be too late to
prevent exploitation so it's not the main purpose of the canaries" (README.md:273-274).

**Security Impact.** The temporal gap between corruption and detection can be unbounded, so canaries
provide essentially no *prevention* of single-shot exploits; they catch sequential/repeated
corruption and raise the cost of imprecise primitives. This is consistent with the stated design
intent. Note that because zero-on-free runs *after* `check_canary` on the same free
(h_malloc.c:834 then 846), a corrupted canary on the slot being freed *is* caught before the slot is
recycled — see Verified Strengths.

**Recommendation.** No change required. Optionally, the WAF-check allocation path could *also*
re-validate the canary of the slot it is handing out at near-zero extra cost (the canary bytes are
already resident), turning some "detected only at next free" cases into "detected at reuse." Minor
defense-in-depth.

---

### HARDEN-04 — Write-after-free zero-scan is defeatable by writing-then-restoring zero, and is best-effort against partial-word writes
**Severity:** Low
**Type:** Design-limitation
**Location:** h_malloc.c:494-512 (`write_after_free_check`), 845-847 (zero-on-free)

**Description.** The WAF detector simply ORs every `u64` of the usable region at allocation time and
aborts if the accumulator is non-zero (h_malloc.c:505-509). It is a *snapshot* taken at reuse, not
continuous instrumentation. Two consequences:
1. An attacker who performs a write-after-free and then **restores the bytes to zero** before the
   slot is reallocated leaves the scan clean — the UAF write itself is invisible. (This is inherent
   to any "verify zeroed at alloc" scheme.)
2. Detection requires the post-free contents to be non-zero. A write whose value is `0` is
   indistinguishable from cleared memory. This is the *intended* tradeoff of zero-based sanitization
   (README.md:391-395: "Zero-based filling has the least chance of uncovering latent bugs, but also
   the best chance of mitigating vulnerabilities"): the goal is to *neutralize* the stale data, and
   the WAF check is a bonus that fires when the attacker writes non-zero.

The detector *does* correctly cover the whole usable region (it scans `S - canary_size`, matching
the zeroed region exactly — h_malloc.c:653/746 vs 846), and the scan stride is a multiple of 8 with
slot sizes 16-aligned, so there is no tail under-scan for slab slots.

**Security Impact.** WAF detection is probabilistic and bypassable by a sufficiently precise
attacker; it should be treated as a tripwire that raises cost, not a guarantee. The combination with
randomized/delayed reuse (quarantine) is what gives it teeth, because the attacker cannot easily
predict *when* the scan happens. Matches documentation.

**Recommendation.** None required. Keep relying on quarantine + zero-on-free for the actual mitigation
and WAF as the tripwire, as designed.

---

### HARDEN-05 — Quarantine is bounded and cheaply flushable: a known number of same-class frees forces reuse of a target slot
**Severity:** Low–Medium
**Type:** Design-limitation (inherent to a fixed-size quarantine)
**Location:** h_malloc.c:850-901 (quarantine logic), 857-886 (length scaling), config/default.mk:10-11

**Description.** Trace of a freed slot `p` (h_malloc.c:850-901):
1. `set_quarantine_slot` marks it (so it cannot be re-handed-out while quarantined; the bitmap is
   checked at h_malloc.c:851 and in alloc via `is_used_slot` staying set — the slot's used bit is
   only cleared at h_malloc.c:914 for the *evicted* pointer).
2. `p` is swapped into a random slot of `quarantine_random[]`; the displaced occupant (or `p`
   itself if the slot was empty/`NULL`) continues.
3. That pointer is swapped into `quarantine_queue[]` at `quarantine_queue_index` (FIFO); the evicted
   queue entry is the one finally freed back to the slab.

With the **default** config (`RANDOM_LENGTH=1`, `QUEUE_LENGTH=1` base, scaled per class) the queue is
a ring of fixed length `L = QUEUE_LENGTH << quarantine_shift` per size class (e.g. 8192 for 16-byte,
64 for 2048-byte, 1 for 128 KiB; see computed table in the audit notes). Because the queue is a
deterministic FIFO of length `L` and the random array merely permutes *which* of the in-flight
pointers is evicted next, an attacker who can free `~L` (worst case `L + random_length`) allocations
of the **same size class** is guaranteed to push any specific earlier free out of the quarantine and
make its slot eligible for reallocation. The random array adds a bounded, *small* random delay (its
length, not an exponential factor), so it does not change the order of magnitude.

**Security Impact.** The quarantine raises the *cost* of UAF-reuse grooming (the attacker must
perform up to ~`L` same-class allocate/free operations, and zero-on-free wipes the stale contents in
the meantime), but it does **not** make reuse impossible or super-linearly expensive. For large size
classes `L` is tiny (down to 1 slot for 128 KiB, 2 for 64-96 KiB), so the quarantine delay there is
negligible — an important caveat to "delayed free." This is the expected behaviour of a fixed-memory
quarantine and is consistent with the design ("scaled to match the total memory of the quarantined
allocations", README.md:289-291), but the security delta is genuinely small for the largest classes.

**Recommendation.** Document that the per-class quarantine depth shrinks to single digits for the
largest slab classes and that an attacker can deterministically flush it with a bounded number of
same-class frees. Deployments worried about UAF on large objects should rely on the large-allocation
path (guard pages + address-space quarantine) where possible. No code defect.

---

### HARDEN-06 — Quarantine and the trailing canary cover only the *usable* region; the canary's 8 bytes are not re-zeroed and not WAF-scanned
**Severity:** Informational / Low
**Type:** Design-limitation
**Location:** h_malloc.c:846 (`memset(p, 0, size - canary_size)`), 653/746 (`write_after_free_check(p, size - canary_size)`)

**Description.** Both zero-on-free and the WAF scan deliberately stop at `size - canary_size`, i.e.
they exclude the final 8 canary bytes. On the next allocation the canary bytes are overwritten by
`set_canary` regardless, so leaving them un-zeroed on free is harmless for data hygiene. The
consequence worth noting: a write that lands **exactly** in the canary region of a *freed* slot
(an 8-byte-precise write-after-free targeting only the canary) is not caught by the WAF scan (which
skips those bytes) and is overwritten on reuse — so it cannot be leveraged and is not a leak, but it
is also not *detected*. This is benign because those bytes carry no user data and are reset before
reuse; the canary's own integrity for the *live* slot is what matters and that is checked on free.

**Security Impact.** None practically; noted for completeness so the "verify zero filling is intact"
claim is understood to mean *the usable region*, not the entire slot.

**Recommendation.** None. Optionally clarify in README that the WAF/zero region is the usable extent
(excludes canary), to avoid over-claiming full-slot coverage.

---

### HARDEN-07 — `light` configuration security delta: loss of UAF-reuse delay and WAF tripwire
**Severity:** Medium (relative to default; `light` is still hardened vs. mainstream allocators)
**Type:** Design-limitation (documented configuration tradeoff)
**Location:** config/light.mk:7,8,10,11 vs config/default.mk; README.md:213-224

**Description.** `light` keeps `ZERO_ON_FREE` and `SLAB_CANARY` but disables:
- `SLAB_QUARANTINE_*` (both 0 → `SLAB_QUARANTINE` is false): freed slots are returned to the slab's
  free list **immediately** (no random/FIFO delay). The entire quarantine block (h_malloc.c:850-901),
  including the `is_quarantine_slot` **double-free check** (h_malloc.c:851-853, the path that emits
  "double free (quarantine)"), is compiled out. Double-free of an *immediately re-freeable* slot is
  still caught by `is_used_slot` (h_malloc.c:829) **only until the slot is reallocated**; a
  free→realloc-elsewhere→free-again of a slot that was handed back out is not a double free and won't
  trip. With quarantine on, the slot stays unusable and double-free is reliably caught while
  quarantined (see double_free_small_delayed test, test_smc.py:75-86).
- `WRITE_AFTER_FREE_CHECK` (false): no zero-scan tripwire at allocation. UAF *detection* is lost;
  UAF *neutralization* via zero-on-free remains.
- `SLOT_RANDOMIZE` (false): `get_free_slot` (h_malloc.c:434-444) becomes a deterministic
  lowest-free-slot scan, making intra-slab placement predictable and improving an attacker's ability
  to position a fresh allocation onto a just-freed slot (which now also has no quarantine delay).
- `GUARD_SLABS_INTERVAL` raised 1→8 (config/light.mk:14): fewer guard slabs between slabs (out of
  this subsystem's core scope but it reduces inter-slab isolation).

**Security Impact.** Under `light`, the realistic UAF story degrades from "delayed + randomized reuse
with a non-zero-write tripwire and reliable double-free detection while quarantined" to "immediate,
largely deterministic reuse with stale data zeroed." That is still meaningfully better than a stock
allocator (canaries + zero-on-free + out-of-line metadata + guard pages remain), but the temporal
safety properties (HARDEN-05) and the double-free-while-quarantined guarantee are substantially
weaker. The README states the positioning accurately (README.md:216-218).

**Recommendation.** Where threat model includes UAF, prefer the `default` config. If `light` is
required for performance, the single highest-value re-enable is the quarantine
(`SLAB_QUARANTINE_QUEUE_LENGTH`), which restores reliable double-free detection and reuse delay; next
is `SLOT_RANDOMIZE`. Already a documented, deliberate tradeoff — no code defect.

---

## Verified Strengths

- **Canary covers every slot and is always placed for non-zero allocations.** `adjust_size_for_canary`
  (h_malloc.c:1492) reserves the 8 trailing bytes at *every* public allocation entry
  (`h_malloc` 1527, `h_calloc` 1537, `h_realloc` 1551, `alloc_aligned` 1502), and `set_canary` is
  called on all four allocation paths (h_malloc.c:654, 691, 718, 747). There is no non-zero small
  allocation path that skips canary placement.

- **Leading-zero-byte correctly absorbs C-string NUL overflows.** With little-endian masking
  `0xffffffffffffff00` (h_malloc.c:516-518), the zeroed byte is the **lowest-address** byte of the
  canary — i.e. the byte immediately after the usable region. A strcpy/strcat that writes one NUL
  terminator one byte past the usable end lands on this guaranteed-zero byte, so the canary still
  matches on free (the test `string_overflow.c` exercises exactly this). Placement and endianness are
  correct.

- **Canary checked before the slot is mutated on free.** In `deallocate_small`, ordering is
  `is_used_slot` (h_malloc.c:829) → `check_canary` (834) → zero-on-free (846) → quarantine (850).
  Corruption of the freed slot's own canary is therefore detected *before* zeroing or recycling, so
  a corrupted slot is never silently reused. (`memory_corruption_check_small` applies the same check
  on `malloc_usable_size`, h_malloc.c:1834.)

- **WAF scan region exactly matches the zeroed region.** Both use `size - canary_size`
  (h_malloc.c:653/746 vs 846), so the invariant "the usable region is all-zero at reuse" is
  self-consistent; there is no off-by-one leaving an unscanned/unzeroed gap inside the usable extent,
  and slot sizes are 16-aligned so the 8-byte-stride scan has no tail remainder.

- **Quarantined slot is genuinely unavailable for reuse.** The freed slot's `used` bit is left set;
  only the pointer *evicted* from the FIFO queue has `clear_used_slot` applied (h_malloc.c:914) after
  `clear_quarantine_slot` (h_malloc.c:900). While in either quarantine layer the slot cannot be
  selected by `get_free_slot`. `is_quarantine_slot` is also checked by `malloc_usable_size`
  (h_malloc.c:1838) and `malloc_object_size` (h_malloc.c:1905) to reject queries on quarantined
  memory.

- **Double-free detection is layered and correct.** A re-free of a still-allocated slot is caught by
  `!is_used_slot` (h_malloc.c:829 → "double free"); a re-free of a slot currently sitting in the
  quarantine is caught by `is_quarantine_slot` (h_malloc.c:851 → "double free (quarantine)"). Tests
  `double_free_small.c` and `double_free_small_delayed.c` confirm both emit fatal errors
  (test_smc.py:75-86).

- **MTE interaction is coherent.** When ARM MTE is active, canary read/write and zero-on-free are
  skipped (h_malloc.c:537-540, 548-552, 838-842) because the tagged mapping provides spatial+temporal
  detection and `arm_mte_tag_and_clear_mem` zeroes on free; the canary value reserves `0` as a
  "disabled" sentinel (h_malloc.c:521-529, 558-560) so a later MTE-disable does not produce false
  canary mismatches. The `calloc` path asserts `ZERO_ON_FREE` under MTE (h_malloc.c:1542-1546).

- **Quarantine length scaling is sound and bounded.** `quarantine_shift` (h_malloc.c:857) gives larger
  classes shorter queues and smaller classes longer ones, keeping total quarantined *bytes* roughly
  constant per class; the index type is chosen correctly (u16 vs u32) based on the worst-case array
  size (h_malloc.c:862-866), and `static_assert`s bound the configured lengths (h_malloc.c:35-44).

- **CSPRNG-backed randomness.** Canary values and quarantine indices come from per-`size_class`
  ChaCha-based `random_state` (random.c:45-156) seeded from `getrandom` and periodically reseeded
  (RANDOM_RESEED_SIZE), with per-arena/per-class independent streams — adequate entropy source for
  the 56-bit canaries and for quarantine index selection.

---

## Claims Assessment

| Claim (README) | Verdict | Justification |
|---|---|---|
| "Random canaries placed after each slab allocation to absorb and then later detect overflows/underflows." (README.md:459-460) | **Holds-with-caveats** | Canary is placed after **every** slot (h_malloc.c:1492, 654/691/718/747) and absorbs small overflows. "Underflows": a write *before* the slot lands in the *previous* slot's canary/slack, detected when that neighbour is freed — coverage is via the neighbour, not the underflowed slot itself. Detection is **free-time only** (HARDEN-03) and misses slack-only overflows (HARDEN-02). |
| "High entropy per-slab random values." (README.md:461) | **Holds-with-caveats** | 56 bits of CSPRNG entropy per slab (h_malloc.c:520, random.c). But it is **per-slab, reused across all slots** (HARDEN-01): a single same-slab leak generalizes. "High entropy" is true per *slab*; effective entropy per *slot* against a leak-capable adversary is lower. |
| "Leading byte is zeroed to contain C string overflows." (README.md:462) | **Holds** | Masked to `0xff..ff00` LE (h_malloc.c:516-518); the zero byte is the lowest-address canary byte, immediately after usable data, correctly absorbing a one-past NUL terminator (verified vs `string_overflow.c`). Entropy cost is the documented 8 of 64 bits (56-bit canary), an accepted tradeoff. |
| "The primary purpose of the canaries is to render small fixed size buffer overflows harmless by absorbing them." + "On free, integrity of the canary is checked." (README.md:267-271) | **Holds** | Absorption is structural (canary = padding); `check_canary` runs on free before any slot mutation (h_malloc.c:834, ordered before zero/quarantine). |
| "Slab allocations are zeroed on free." (README.md:445) | **Holds-with-caveats** | True for the **usable** region (`memset(p, 0, size - canary_size)`, h_malloc.c:846) when `ZERO_ON_FREE`. Caveats: the 8 canary bytes are intentionally excluded (HARDEN-06, benign — reset on reuse); under MTE, zeroing is done by `arm_mte_tag_and_clear_mem` instead (h_malloc.c:838-842); with `ZERO_ON_FREE=false` it is *not* zeroed on free (then `calloc` zeroes on alloc instead, h_malloc.c:1539-1541). |
| "Detection of write-after-free for slab allocations by verifying zero filling is intact at allocation time." (README.md:446-447) | **Holds-with-caveats** | Implemented (h_malloc.c:494-512), scans the full usable region on reuse from empty/partial slabs. Caveats: it is a best-effort tripwire — bypassable by write-then-restore-zero and blind to zero-valued writes (HARDEN-04); disabled in `light` (HARDEN-07); skipped under MTE (h_malloc.c:500-503, redundant there). |
| "Delayed free via a combination of FIFO and randomization for slab allocations." (README.md:448) | **Holds-with-caveats** | FIFO queue + random-array swap implemented exactly as described (h_malloc.c:859-894). Caveat: the delay is **bounded and deterministically flushable** with ~`L` same-class frees, and `L` shrinks to single digits (down to 1) for the largest size classes (HARDEN-05). It delays/raises cost; it does not prevent reuse. |
| "proper double-free detection for quarantined allocations." (README.md:58) | **Holds** | `is_quarantine_slot` (h_malloc.c:851) deterministically catches re-free while quarantined; `is_used_slot` (h_malloc.c:829) catches re-free while live. Both verified by tests (test_smc.py:75-86). Only valid in `default`; in `light` the quarantine layer (and thus the "double free (quarantine)" path) is absent (HARDEN-07). |
| (`light`) "still being far more secure than mainstream allocators." (README.md:216-218) | **Holds** | Accurate: `light` retains canaries, zero-on-free, out-of-line protected metadata and guard slabs; it drops quarantine/WAF/slot-randomization, which weakens temporal safety and double-free-while-quarantined but stays above stock allocators (HARDEN-07). |

---

### Summary judgement
The canary, zero-on-free, WAF, and quarantine implementations are correct, internally consistent, and
faithful to their documentation. No memory-safety bug was found in this subsystem. Every finding is
either an explicitly-documented design tradeoff (per-slab canary reuse, slack-space non-detection,
free-time-only checking, bounded/flushable quarantine, zero-based WAF) or a configuration-delta
observation (`light`). The strongest honest caveats for downstream consumers: (1) one same-slab leak
defeats the canary for the whole slab (HARDEN-01), and (2) the quarantine delay is bounded and trivial
for the largest size classes (HARDEN-05). These are limitations of the chosen performance/security
balance, not defects.
