# Randomness & CSPRNG — Audit Findings

**Target:** GrapheneOS hardened_malloc @ commit `9e88c14`
**Subsystem:** CSPRNG (ChaCha8 keystream) and all randomization-based mitigations
**Files audited:** `random.c`, `random.h`, `chacha.c`, `chacha.h`, consumption sites in `h_malloc.c`, `config/default.mk`, `util.h`
**Auditor stance:** Authorized, defensive security audit. Findings are classified honestly as Bug / Design-limitation / Defense-in-depth.

---

## Subsystem Overview

The randomization layer is built on a ChaCha8 keystream generator wrapped in a small per-instance cache:

- **`struct random_state`** (`random.h:10-15`): `{ unsigned index; unsigned reseed; chacha_ctx ctx; u8 cache[256]; }`. Each instance is a self-contained CSPRNG with a 256-byte output buffer.
- **Seeding** (`random.c:27-34`, `random_state_init`): pulls `CHACHA_KEY_SIZE (32) + CHACHA_IV_SIZE (8) = 40` bytes from the kernel via `getrandom(..., 0)`, then keys ChaCha8 (256-bit key) and sets the 64-bit nonce. The 64-bit block counter is zeroed in `chacha_ivsetup`.
- **Derived seeding** (`random.c:36-43`, `random_state_init_from_random_state`): seeds a new instance by drawing 40 bytes from a *parent* CSPRNG instead of the OS. Used at init to fan out one OS-seeded CSPRNG into the per-arena/per-size-class instances.
- **Refill / reseed** (`random.c:45-52`): each 256-byte cache refill increments `reseed += 256`; when `reseed >= RANDOM_RESEED_SIZE (256 KiB)` the instance re-keys from the OS via `random_state_init`. So reseed-from-OS happens once per 256 KiB of consumed keystream.
- **Consumers**: `get_random_u16/u32/u64` (fixed-width draws from cache), `get_random_bytes` (bulk; bypasses cache for sizes > 128 B), and the Lemire uniform-range functions `get_random_u16/u32/u64_uniform`.

**CSPRNG instances** (matching the README "Randomness" claim):
- One per `(arena, small size class)` — `struct size_class.rng` (`h_malloc.c:307`), `N_ARENA (4) × N_SIZE_CLASSES (49)` instances.
- One for the large-allocation region allocator — `struct region_allocator.rng` (`h_malloc.c:985`).
- One transient init CSPRNG (`h_malloc.c:1264-1268`), OS-seeded, used to derive the others, then `deallocate_pages`'d (`h_malloc.c:1328`).

**Randomness consumers in `h_malloc.c`:**
- Slot selection: `get_free_slot` → `get_random_u16_uniform(rng, slots)` (`h_malloc.c:415`), gated on `SLOT_RANDOMIZE`.
- Slab canary: `set_slab_canary_value` → `get_random_u64(rng) & canary_mask` (`h_malloc.c:520`).
- Large-allocation guard sizing: `get_guard_size` → `get_random_u64_uniform` (`h_malloc.c:1383-1384`).
- Quarantine slot index (small): `get_random_u16_uniform`/`u32_uniform` (`h_malloc.c:863-865`).
- Free-slab quarantine index: `get_random_u16_uniform` (`h_malloc.c:784`).
- Region quarantine index (large): `get_random_u64_uniform` (`h_malloc.c:1038`).
- Init-time region base offsets / metadata guard size (`h_malloc.c:1271, 1311`).

**Memory protection of CSPRNG state:** all long-lived `rng` instances are embedded in `struct allocator_state` (`h_malloc.c:1004-1014`), i.e. the isolated metadata region. After init, `ro` is `memory_protect_ro` (`h_malloc.c:1332`) and, when `CONFIG_SEAL_METADATA` is enabled, the metadata region is PKEY-sealed (`PKEY_DISABLE_ACCESS`) outside of unseal windows (`h_malloc.c:1192-1196`). Per-instance access is serialized under the owning `c->lock` / `ra->lock`.

---

## Findings

### RNG-01 — ChaCha8 keystream implementation is correct and faithful to the reference
**Severity:** Informational (positive)
**Type:** Verified strength (not a finding against the code)
**Location:** `chacha.c:1-177`

**Description:** The implementation is the DJB `chacha-merged.c` reference with the message-XOR removed, producing a pure keystream. I verified each spec-relevant element:
- Constants: `sigma = "expand 32-byte k"` (`chacha.c:44`), the 256-bit-key constant. Loaded into state words 0–3 little-endian (`chacha.c:47-50`).
- Key → words 4–11, nonce → words 14–15, counter → words 12–13, all little-endian (`chacha.c:51-66`).
- Round count: `rounds = 8` (`chacha.c:8`), loop `for (i = rounds; i > 0; i -= 2)` performs 4 double-rounds = 8 rounds = ChaCha8 (`chacha.c:114-123`). Correct.
- Quarter-round rotation constants 16/12/8/7 (`chacha.c:38-42`) and the column/diagonal round pattern (`chacha.c:115-122`) match the spec exactly.
- Output: working state added back to the original input words (`chacha.c:124-139`) and serialized little-endian (`chacha.c:147-162`). Correct "add feed-forward" step.
- Counter: 64-bit, `j12` incremented per 64-byte block with carry into `j13` (`chacha.c:141-145`); the updated counter is written back to `x->input[12/13]` on return (`chacha.c:170-171`), so successive calls continue the stream rather than repeating block 0.

**Security Impact:** None — this is the reassuring baseline. No keystream-weakening bug, no truncated rounds, no endian defect.

**Recommendation:** None. Keep tracking upstream ChaCha reference fixes (none outstanding).

---

### RNG-02 — Lemire uniform-range generators are unbiased; preconditions are satisfied in practice
**Severity:** Informational (positive)
**Type:** Verified strength
**Location:** `random.c:88-102` (u16), `:116-129` (u32), `:143-156` (u64)

**Description:** The "highly optimized random range generation" claim refers to Lemire's *Fast Random Integer Generation in an Interval* (the multiply-shift method with rejection). I verified correctness for the u16 variant (the others are structurally identical at 32/64/128-bit widths):
- `multiresult = random * bound` is computed in a double-width type (`u32` for u16 input, `u64` for u32, `u128` for u64), so no truncation of the product. `random.c:89-90, 117-118, 144-145`.
- Return value `multiresult >> 16` (resp. `>> 32`, `>> 64`) lands in `[0, bound)`. This is the exact Lemire bit-trick and is uniform *after* rejection. `random.c:101, 128, 155`.
- Rejection threshold `(u16)-bound % bound` = `(2^16 mod bound)` is computed correctly; the `(u16)` cast at `random.c:94` is explicitly needed to defeat C integer promotion of `-bound` to `int` (which would otherwise compute `2^32 mod bound` and over-reject — still unbiased, but the cast keeps it correct/efficient). The rejection loop redraws only when `leftover < threshold` (`random.c:92-99`), which is exactly the set of products that would otherwise bias the result. **No modulo bias.**
- The `u64` variant relies on `u128` (`util.h:46`) and a well-defined `>> 64` on a 128-bit type (`random.c:155`) — defined behavior since the operand width is 128 bits.

**Quantitative check of preconditions:** the algorithm is only unbiased when `bound` fits in the input width. All `get_random_u16_uniform` call sites pass bounds that are provably ≤ 2^16:
- `get_free_slot`: `bound = slots`, and `max(size_class_slots[]) = 256` (`h_malloc.c:180-195`). ✓
- Small-slab quarantine: the `#if` at `h_malloc.c:862` selects the u16 path only when `SLAB_QUARANTINE_RANDOM_LENGTH << 13 ≤ UINT16_MAX`, and falls back to `u32_uniform` otherwise. ✓ (explicit guard)
- `FREE_SLABS_QUARANTINE_RANDOM_LENGTH`: a `static_assert(... < (u16)-1, ...)` at `h_malloc.c:783` enforces the bound. ✓
- `REGION_QUARANTINE_RANDOM_LENGTH (256)` and guard-size bounds use the u64 variant. ✓

**Security Impact:** Slot selection, canary, guard sizing and quarantine indices are drawn from a genuinely uniform distribution; there is no exploitable skew (e.g. low slots being preferentially chosen) that would weaken layout randomization.

**Recommendation:** None. The bound preconditions are enforced by `static_assert`/`#if`; this is good defensive engineering. (Optional: a one-line comment on each uniform function stating "bound must be representable in the input width" would make the invariant explicit for future callers.)

---

### RNG-03 — Fork safety: all CSPRNGs are reseeded from the OS in the child
**Severity:** Informational (positive)
**Type:** Verified strength
**Location:** `post_fork_child` — `h_malloc.c:1220-1233`

**Description:** A classic CSPRNG-in-a-library failure mode is `fork()` duplicating CSPRNG state so parent and child emit identical streams (→ identical heap layouts, identical canaries). hardened_malloc registers `post_fork_child` via `pthread_atfork` (`h_malloc.c:1340`) and, in the child:
- reseeds the region-allocator CSPRNG: `random_state_init(&ro.region_allocator->rng)` (`h_malloc.c:1224`), which pulls fresh OS entropy;
- reseeds **every** per-(arena, size-class) CSPRNG: nested loop calling `random_state_init(&c->rng)` for all `N_ARENA × N_SIZE_CLASSES` instances (`h_malloc.c:1225-1231`).

Because `random_state_init` always calls `get_random_seed` → `getrandom` (`random.c:28-30`), this is a true re-key from the kernel, not a counter bump. The reseed is eager (done in the atfork handler), not lazy, so there is no window in which a freshly forked child could draw from inherited state.

**Security Impact:** Parent/child divergence is guaranteed for slot selection, canaries, guard sizes and quarantine ordering. No identical-layout weakness across fork.

**Recommendation:** None. One residual note: this relies on `pthread_atfork` firing, which does **not** cover `vfork`/`clone`-based process creation that bypasses pthread handlers, nor a child that calls `fork()` from an async-signal context where the handler can deadlock on the metadata lock. These are inherent libc limitations, captured in RNG-07.

---

### RNG-04 — `getrandom` is invoked with flags `0`; can block before the kernel pool is initialized
**Severity:** Low
**Type:** Design-limitation (documented tradeoff)
**Location:** `get_random_seed` — `random.c:10-25` (call at `:15`)

**Description:** Seeding uses `getrandom(buf, size, 0)`. With `flags == 0`, `getrandom` draws from the `urandom` source but **blocks** until the kernel CSPRNG is first initialized (early boot). The loop handles `EINTR` and partial reads correctly and treats `r <= 0` (including a `0` return) as fatal (`random.c:18-20`). This is the correct *safety* choice: it never proceeds with low-entropy seed material, unlike a `GRND_NONBLOCK` design that could silently fall back to weak seeds.

The tradeoff: the very first allocation on a not-yet-seeded kernel can block. For a userspace allocator on GrapheneOS/Android this is effectively a non-issue (the kernel RNG is initialized long before app processes run), but it is a hard dependency worth recording. There is also no use of `GRND_RANDOM` (correct — the blocking-`urandom` semantics are exactly what is wanted) and no `getentropy`/`/dev/urandom` fallback path if `getrandom` is unavailable (acceptable: the supported targets always provide it, and a fallback would risk weaker seeding).

**Security Impact:** No entropy weakness — the design strictly fails closed. The only effect is a potential early-boot stall, not a randomization-quality problem. On a hypothetical platform where `getrandom` is missing/ENOSYS, `r == -1` with `errno != EINTR` → `fatal_error`, i.e. the allocator aborts rather than degrades. That is the desired behavior for a hardened allocator.

**Recommendation:** No change required. If broader portability is ever a goal, document that `getrandom(0)` blocking semantics are intentional and that absence of `getrandom` is treated as fatal by design.

---

### RNG-05 — Reseed interval (256 KiB) bounds backtracking/prediction-resistance window; derived CSPRNGs reseed independently
**Severity:** Low / Informational
**Type:** Design-limitation (documented tradeoff)
**Location:** `RANDOM_RESEED_SIZE` — `random.h:8`; reseed logic `random.c:45-52`

**Description:** The README claims the cipher is "regularly reseeded from the OS to provide backtracking and prediction resistance." Verified mechanics:
- `RANDOM_RESEED_SIZE = 256 * 1024` (`random.h:8`); each refill adds 256 (`random.c:51`); when `reseed >= 256 KiB` the next refill triggers a full OS re-key (`random.c:46-48`). So OS reseed occurs once per **256 KiB of keystream per instance**.
- The reseed is checked **before** the refill that crosses the threshold (`random.c:46`), so the stale `ctx` is discarded and replaced before more output is produced from it — correct ordering for forward secrecy of *future* output.

Backtracking/prediction-resistance characterization:
- **Within** a 256 KiB window, ChaCha8 is invertible given the key, so an attacker who recovers the in-memory CSPRNG state (key + counter) via a metadata disclosure can compute **all** outputs since the last reseed (backtracking) and predict all outputs until the next reseed (prediction) — up to ~256 KiB / draw in either direction. The 256 KiB window therefore is the true granularity of the "resistance," not per-draw. The README's framing ("negligible cost… interval adjusted until no significant perf impact") is honest about this being a performance/security knob.
- ChaCha is not a "fast-key-erasure"/forward-secure construction (no per-block re-keying), so backtracking resistance *between* draws within a window is not provided. This is an explicit, reasonable tradeoff for an allocator whose threat model already assumes metadata confidentiality (sealed/`PROT_NONE` metadata) — if the attacker can read the live CSPRNG state, they can usually read the layout directly anyway.

**Derived-CSPRNG nuance (positive):** the per-size-class/region CSPRNGs are seeded once from the init CSPRNG (`random_state_init_from_random_state`, `h_malloc.c:1286, 1308`) but each then reseeds **from the OS** thereafter (`refill` always calls `random_state_init`, which uses `getrandom`, `random.c:47`). So the one-time derivation from a shared parent does not create a long-lived correlation: after each instance consumes its first 256 KiB it is independently OS-seeded. The transient init CSPRNG itself is wiped via `deallocate_pages` (`h_malloc.c:1328`).

**Security Impact:** Bounded and acceptable. The practical exposure is "an attacker with a one-shot read of CSPRNG metadata learns ≤256 KiB of past/future randomness for that one instance." Given the metadata is sealed and the same disclosure typically reveals the layout itself, this does not materially lower the bar.

**Recommendation:** Defense-in-depth (optional): a *time*-based reseed component (e.g. also reseed if N seconds elapsed) would cap the prediction window for low-throughput size classes that may take a long time to consume 256 KiB. Not necessary for the stated threat model.

---

### RNG-06 — Slab canary entropy is 56 bits (leading byte intentionally zeroed); honest tradeoff
**Severity:** Informational
**Type:** Design-limitation (documented tradeoff)
**Location:** `set_slab_canary_value` — `h_malloc.c:514-532`; `canary_size` — `h_malloc.c:56`

**Description:** Canary is one `u64` (`canary_size = sizeof(u64)`, `h_malloc.c:56`) drawn from `get_random_u64(rng)` and masked with `canary_mask = 0xffffffffffffff00` on little-endian (`h_malloc.c:516-520`). The masking zeroes the **leading** (lowest-address, first-written) byte so that a C-string overflow that stops at a NUL terminator cannot incrementally leak/forge the canary, and to "contain C string overflows" (README:462). Net entropy is therefore **56 bits**, per slab (one canary value shared by all slots in a slab; `canary_value` is in `slab_metadata`).

When ARM MTE is active, canaries are not used (the function early-returns logic and `set_canary`/`check_canary` skip when `is_memtag_enabled()`); the `canary_value == 0` → `0x100` adjustment (`h_malloc.c:521-529`) reserves 0 to mean "MTE-disabled sentinel," which very slightly reduces the value space but is irrelevant to entropy at 56 bits.

**Security Impact:** 56-bit unforgeable-on-blind-guess canary per slab is strong; brute-forcing requires ~2^55 attempts on average against a non-leaking target, with each wrong guess crashing the process (so online guessing is infeasible). The per-slab (not per-slot) scope means a leak of one slot's trailing canary discloses the canary for every other slot in that same slab — a deliberate memory/perf tradeoff, not a flaw. The zeroed leading byte is a sound mitigation that costs 8 bits.

**Recommendation:** None required. The 56-bit/per-slab/zero-leading-byte design is a well-reasoned tradeoff and matches the documentation.

---

### RNG-07 — `pthread_atfork`-based reseed does not cover `vfork`/raw `clone`; child reseed runs under metadata lock
**Severity:** Low
**Type:** Design-limitation
**Location:** `h_malloc.c:1340` (registration), `post_fork_child` `h_malloc.c:1220-1233`

**Description:** Reseed-on-fork is correct for `fork()`/`pthread_atfork`-aware paths (RNG-03), but:
1. `vfork()` and direct `clone()`/`syscall(SYS_clone)` without glibc's fork wrapper do **not** invoke `pthread_atfork` child handlers, so a child created that way inherits parent CSPRNG state. In practice such children almost always immediately `exec` (so no allocations occur with the inherited state), which is why this is low-severity; but a `vfork` child that performed allocations before `exec` could share the parent's stream.
2. `post_fork_child` re-inits mutexes and reseeds, but the work happens after `thread_unseal_metadata()` and touches the metadata region while the process may be in an async-signal-unsafe state (a fork from a multithreaded process where another thread held an internal lock). hardened_malloc mitigates this by taking `full_lock` in the prepare handler (`h_malloc.c:1340`, `full_lock`), so locks are in a known state across fork — this is the correct pattern and avoids the classic atfork deadlock.

**Security Impact:** Narrow. Only `vfork`/raw-clone children that allocate before `exec` could reuse the parent stream; this is an inherent limitation of any userspace CSPRNG relying on `pthread_atfork`, not specific to this code. The Linux kernel `getrandom`/MADV_WIPEONFORK style protections are not used here.

**Recommendation:** Defense-in-depth (optional, and partly outside the allocator's control): on Linux, mapping the CSPRNG cache/state pages with `MADV_WIPEONFORK` would zero the cache (forcing a refill→reseed) in *any* child regardless of fork mechanism. This would need the refill path to detect a wiped/zeroed state and re-key. Non-trivial and likely unjustified given the `vfork→exec` norm, but it is the only mechanism that closes the raw-`clone` gap.

---

### RNG-08 — Large-allocation guard-region size granularity is page-quantized with divisor 2
**Severity:** Informational
**Type:** Design-limitation (documented tradeoff)
**Location:** `get_guard_size` — `h_malloc.c:1383-1384`; `GUARD_SIZE_DIVISOR` — `config/default.mk:15`

**Description:** Guard size = `(get_random_u64_uniform(state, size / PAGE_SIZE / GUARD_SIZE_DIVISOR) + 1) * PAGE_SIZE`. With `GUARD_SIZE_DIVISOR = 2`, the guard is a uniformly random multiple of the page size in `[1 page, size/(2·PAGE_SIZE) pages]`. The randomization is **page-granular** (4 KiB steps), so the entropy of the guard offset is `log2(size / PAGE_SIZE / 2)` bits — e.g. for a 1 MiB allocation, `log2(256/2) = 7` bits (~128 distinct guard sizes). Smaller large-allocations get correspondingly less guard-size entropy; a 2-page allocation (`size/PAGE_SIZE/2 == 0` after integer division when `size == 2 pages`) would make `bound == 0`.

**Bound-zero check:** `get_random_u64_uniform(state, 0)` would compute `random * 0 == 0`, `leftover = 0 < bound(0)` is false, returning `0 >> 64 == 0`; `+1` ⇒ a 1-page guard. So a `bound==0` does **not** divide-by-zero or loop forever here — `multiresult >> 64` with `bound==0` returns 0 cleanly. (Worth noting because Lemire with `bound==0` is a footgun in general; here it degrades gracefully to a fixed 1-page guard.) The large-allocation path is only reached for sizes above the slab threshold, so the smallest such `size/PAGE_SIZE/2` is comfortably ≥ 1 for the real minimum large size, making `bound==0` unreachable in practice; the graceful degradation is a safety margin, not a live path.

**Security Impact:** Guard randomization meaningfully increases the difficulty of reliably landing adjacent to a target large allocation, but the entropy scales only with allocation size and is page-granular. This is the expected behavior and matches "Randomly sized guard regions."

**Recommendation:** None. (Defense-in-depth: a smaller `GUARD_SIZE_DIVISOR` increases guard entropy at the cost of address-space/commit overhead — a tunable, already exposed as config.)

---

### RNG-09 — Thread-safety of per-instance CSPRNG relies on caller-held size-class/region lock (correct, but undocumented at the RNG layer)
**Severity:** Informational
**Type:** Verified strength (with documentation note)
**Location:** consumers under lock — e.g. `h_malloc.c:649/669/687/710/714/733` (slot+canary inside `c->lock`), `h_malloc.c:817` + `863-868` (quarantine under `c->lock`), `h_malloc.c:1035-1040` (region quarantine under `ra->lock`); RNG functions `random.c` (no internal locking)

**Description:** `struct random_state` has no internal synchronization; `get_random_*` mutate `state->index`, `state->cache`, `state->reseed`, and `ctx`. Correctness depends on each instance only being touched while the owning lock is held. I verified the small-allocation paths take `c->lock` before any `get_free_slot`/`set_slab_canary_value`/quarantine draw (e.g. `mutex_lock(&c->lock)` at `h_malloc.c:817` precedes the quarantine draw at `:863`; the allocation paths at `:649/669/687/710/714/733` are all within the `c->lock` critical section of `allocate_small`). Region-allocator draws are under `ra->lock` (`h_malloc.c:1035`). The init-time fan-out runs single-threaded under `init_lock`. So every CSPRNG instance is effectively single-writer-at-a-time. This is exactly the design the README describes ("fit into the fine-grained locking model without … TLS").

**Security Impact:** No data race that could corrupt CSPRNG state (which could otherwise produce duplicated/garbage randomness). The locking discipline is sound.

**Recommendation:** Defense-in-depth: add a comment in `random.h`/`random.c` stating that `struct random_state` is **not** internally synchronized and the caller must hold the owning lock. This prevents a future caller from drawing from `c->rng` outside the lock.

---

### RNG-10 — `get_random_bytes` bulk path correctly bypasses the cache but does not advance `reseed` accounting
**Severity:** Low
**Type:** Design-limitation / minor inconsistency
**Location:** `get_random_bytes` — `random.c:54-74`

**Description:** For `size > RANDOM_CACHE_SIZE/2 (128)`, `get_random_bytes` calls `chacha_keystream_bytes` directly into the caller buffer (`random.c:56-58`) "to avoid needless copying." This path **does not** update `state->reseed`, so large bulk draws consume keystream from the ChaCha counter without counting toward the 256 KiB OS-reseed budget. In the current codebase the only `get_random_bytes` caller is `random_state_init_from_random_state` (40 bytes, which is ≤128 and so takes the *cached* path, `random.c:38`), so this inconsistency is not exercised today. But a future caller requesting >128 bytes repeatedly could advance the ChaCha counter arbitrarily far while `reseed` never reaches the threshold, extending the prediction window beyond the intended 256 KiB for that instance.

Note also that the bulk path advances the same `ctx` counter used by the cached path, so there is no keystream reuse/overlap between the two paths — correctness is fine; only the *reseed budget accounting* is incomplete.

**Security Impact:** Currently none (no >128-byte caller). Latent: violates the "reseed every 256 KiB" invariant for hypothetical large bulk consumers, weakening prediction resistance for that instance. Worth fixing defensively since the function is a general API.

**Recommendation:** Account for the bypassed bytes, e.g. add `state->reseed += size;` (and trigger `random_state_init` if it crosses the threshold) in the bulk branch, mirroring `refill`. Low effort; closes the invariant gap.

---

## Verified Strengths

- **Cryptographically sound core:** ChaCha8 keystream matches the DJB reference in constants, round count (8), little-endian word handling, quarter-round schedule, feed-forward add, and 64-bit counter carry (`chacha.c:8,44,47-66,114-145,147-162`). No entropy-reducing bug.
- **Unbiased range generation:** Lemire multiply-shift-with-rejection is implemented correctly with double-width products and a correct `(2^w mod bound)` threshold; no modulo bias (`random.c:88-102,116-129,143-156`). Bound preconditions enforced by `static_assert`/`#if` (`h_malloc.c:783,862`).
- **Per-domain CSPRNG isolation:** separate instances per `(arena, size class)`, per region allocator, and a discarded init instance — exactly as documented (`h_malloc.c:307,985,1264-1328`).
- **Fail-closed OS seeding:** `getrandom(...,0)` blocks until kernel pool ready; partial reads handled; any failure is fatal (`random.c:10-25`).
- **Correct fork handling:** all CSPRNGs OS-reseeded eagerly in `post_fork_child`, with `full_lock` taken in the prepare handler to avoid atfork lock-state corruption (`h_malloc.c:1220-1233,1340`).
- **Forward reseed ordering:** reseed check precedes the refill that would cross the threshold, so stale keys are retired before further output (`random.c:46-49`).
- **Memory protection of CSPRNG state:** all live `rng` state is inside the isolated metadata region, set read-only post-init (`memory_protect_ro`, `h_malloc.c:1332`) and PKEY-sealable (`CONFIG_SEAL_METADATA`, `util.h:87-95`, `h_malloc.c:1192-1196`); the transient init CSPRNG is unmapped after use (`h_malloc.c:1328`).
- **Thread safety:** every CSPRNG draw occurs under the owning size-class/region lock; no internal race (`h_malloc.c:817,1035`, init under `init_lock`).
- **High-entropy canary with string-overflow containment:** 56-bit per-slab canary, leading byte zeroed (`h_malloc.c:514-520`).

---

## Claims Assessment

| Claim (README "Randomness" / "Security properties") | Verdict | Justification |
|---|---|---|
| "random number generation … based on generating a keystream from a stream cipher (ChaCha8)" | **Holds** | `chacha.c` is a correct ChaCha8 keystream (RNG-01); `random.c` wraps it with a cache. |
| "Separate CSPRNGs are used for each small size class in each arena, large allocations and initialization" | **Holds** | `struct size_class.rng` per `(arena,class)` (`h_malloc.c:307`), `region_allocator.rng` (`:985`), transient init CSPRNG (`:1264`). |
| "The stream cipher is regularly reseeded from the OS to provide backtracking and prediction resistance" | **Holds-with-caveats** | Re-keys from `getrandom` every 256 KiB per instance (RNG-05). Resistance granularity is the 256 KiB window, not per-draw; within a window ChaCha is invertible. Bulk-draw path doesn't count toward the budget (RNG-10, latent). |
| "The random range generation functions are a highly optimized implementation" (implied: correct/unbiased) | **Holds** | Lemire method, verified unbiased with correct double-width products and rejection threshold; preconditions enforced (RNG-02). |
| Canary: "High entropy per-slab random values"; "Leading byte is zeroed to contain C string overflows" | **Holds** | 56-bit entropy per slab from `get_random_u64` masked `0x…00` (RNG-06). "High entropy" is fair for 56 bits with crash-on-mismatch online cost. |
| Guard regions: "Randomly sized guard regions for large allocations" | **Holds** | `get_guard_size` draws a uniform page-granular size in `[1, size/(2·PAGE_SIZE)]` pages (RNG-08). Entropy scales with allocation size. |
| Slot selection: "Random slot selection within slabs" | **Holds** | `get_free_slot` uses `get_random_u16_uniform(rng, slots)` to randomize the linear-search start, gated on `SLOT_RANDOMIZE` (default true) (RNG-02; `h_malloc.c:412-433`). Uniform, no skew. |
| CSPRNG state "protected via the same approach taken for the rest of the metadata" | **Holds** | State lives in `allocator_state` metadata region; `memory_protect_ro` + optional PKEY seal; init CSPRNG unmapped (Verified Strengths). |
| Reseed-on-fork (no identical parent/child streams) | **Holds-with-caveats** | Eager OS reseed of all CSPRNGs in `post_fork_child` (RNG-03). Does not cover `vfork`/raw `clone` that bypass `pthread_atfork` (RNG-07) — inherent libc limitation; such children normally `exec` immediately. |

---

## Summary of Findings

| ID | Severity | Type | Title |
|---|---|---|---|
| RNG-01 | Info (+) | Strength | ChaCha8 implementation correct and faithful to reference |
| RNG-02 | Info (+) | Strength | Lemire uniform generators unbiased; preconditions enforced |
| RNG-03 | Info (+) | Strength | All CSPRNGs OS-reseeded in `post_fork_child` |
| RNG-04 | Low | Design-limitation | `getrandom(…,0)` can block pre-seed; fails closed (correct) |
| RNG-05 | Low/Info | Design-limitation | 256 KiB reseed window bounds backtracking/prediction resistance |
| RNG-06 | Info | Design-limitation | 56-bit per-slab canary (leading byte zeroed) — sound tradeoff |
| RNG-07 | Low | Design-limitation | atfork reseed misses `vfork`/raw `clone`; runs under metadata lock |
| RNG-08 | Info | Design-limitation | Guard size page-granular, entropy scales with allocation size |
| RNG-09 | Info | Strength | Per-instance CSPRNG safe under caller lock (document the invariant) |
| RNG-10 | Low | Design-limitation | `get_random_bytes` bulk path skips `reseed` accounting (latent) |

**Verdict:** The CSPRNG and randomization subsystem is **sound and well-engineered**; the ChaCha8 core and the Lemire uniform generators are correct (no entropy loss, no modulo bias, no keystream reuse), fork handling reseeds from the OS, and CSPRNG state is properly isolated. There are **no real bugs**; the only actionable item is the defensive `reseed`-accounting fix in `get_random_bytes` (RNG-10), with the remainder being inherent design tradeoffs that the documentation already characterizes honestly.
