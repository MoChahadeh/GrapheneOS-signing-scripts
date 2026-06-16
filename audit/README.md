# GrapheneOS `hardened_malloc` — Security Audit

An AI-automated, claims-driven **defensive security audit** of GrapheneOS
[`hardened_malloc`](https://github.com/GrapheneOS/hardened_malloc) at commit
`9e88c14`, evaluating whether the allocator's hardening claims hold up against its
implementation. This is part of a series of security audits of the
security-relevant portions of GrapheneOS that differ from stock AOSP.

## Start here

➡️ **[`SECURITY_AUDIT.md`](./SECURITY_AUDIT.md)** — the comprehensive top-level
report: executive summary, methodology, architecture overview, consolidated
findings, the security-claims-vs-implementation matrix, and prioritized
recommendations.

## Headline result

**No memory-safety vulnerabilities were found.** The allocator's core security
properties hold (11 of 24 unconditionally, 13 with documented caveats; **none
false**). Findings are dominated by inherent design tradeoffs and a few
low-severity, defense-in-depth hardening suggestions — the expected outcome for a
mature, heavily-reviewed, widely-deployed allocator.

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 (config-relative) |
| Low–Medium | 2 |
| Low | 17 |
| Informational | 30 |

## Detailed per-subsystem reports

| # | Subsystem | Report |
|---|---|---|
| 01 | Core slab allocator | [`findings/01-core-slab-allocator.md`](./findings/01-core-slab-allocator.md) |
| 02 | Large allocations & region table | [`findings/02-large-alloc-regions.md`](./findings/02-large-alloc-regions.md) |
| 03 | Randomness & CSPRNG | [`findings/03-randomness-csprng.md`](./findings/03-randomness-csprng.md) |
| 04 | Canaries, quarantine & write-after-free | [`findings/04-canary-quarantine-waf.md`](./findings/04-canary-quarantine-waf.md) |
| 05 | Memory primitives, isolation & MPK | [`findings/05-memory-isolation-mpk.md`](./findings/05-memory-isolation-mpk.md) |
| 06 | Memory tagging (MTE), C++ & API surface | [`findings/06-mte-cpp-api.md`](./findings/06-mte-cpp-api.md) |

## Method, in brief

The allocator was decomposed into six security-critical subsystems, each reviewed
in depth by a dedicated specialist reviewer against the specific properties
GrapheneOS advertises for that subsystem. The lead auditor independently verified
the highest-impact technical claims against the source. Reviewers were instructed
to be intellectually honest, cite exact `file:line` evidence, document strengths
as well as weaknesses, and **not** to fabricate findings. See
[`SECURITY_AUDIT.md` §2](./SECURITY_AUDIT.md#2-scope--methodology) for the full
methodology and limitations.

## Scope note

This is a static source review of the upstream allocator at a fixed commit. No
dynamic analysis (fuzzing/sanitizers) or on-hardware ARM MTE execution was
performed. The upstream source is checked out locally for analysis only and is not
vendored into this repository.
