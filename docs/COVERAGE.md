# Coverage and Completion Contract

This page prevents the table of contents from being mistaken for completed
functionality. “Covered” requires all four artifacts:

1. production implementation;
2. normal and adversarial tests;
3. a step-by-step chapter;
4. links to the governing specification.

## Status vocabulary

| Status | Meaning |
|---|---|
| Covered | all four artifacts exist |
| Partial | useful implementation exists, but behavior or teaching material is incomplete |
| Planned | inside the book's promised scope but not implemented yet |
| Out of scope | explained and mapped to specifications, but not promised as final code |

## Supported product scope

The target is a small but usable DNS implementation that can:

- encode and safely decode ordinary DNS messages;
- act as a stub client over UDP and TCP;
- perform bounded iterative resolution from configured root hints;
- cache positive and negative answers with decreasing TTLs;
- serve validated authoritative zone data over UDP and TCP;
- answer exact, CNAME, delegation, wildcard, NODATA, and NXDOMAIN cases;
- expose runnable query and server command-line programs;
- reject malformed input without throwing, hanging, or allocating without limits.

It is not intended to replace a production public resolver. DNSSEC validation,
dynamic update, zone transfer, TSIG, encrypted DNS transports, and production
operations are separate advanced projects.

## Implementation coverage

| Area | Status | Implementation | Tests | Missing before Covered |
|---|---|---|---|---|
| Absolute domain names | Partial | `DomainName` | examples + properties | escaped presentation form and IDNA boundary |
| Header/questions/sections | Partial | `Protocol`, `MessageCodec` | fixtures + round trips | opcode-specific message validation |
| A, AAAA, NS, CNAME, PTR, MX, TXT, SOA, SRV | Partial | typed `RecordData` | codec round trip | per-type malformed RDATA tables and chapters |
| Unknown RR preservation | Partial | `RecordData.Unknown` | round trip indirectly | explicit property and class/type registry chapter |
| Name compression decode | Partial | loop/bounds checks | adversarial fixtures | pointer-hop budget and more multi-hop fixtures |
| Name compression encode | Partial | owner-name suffixes | repeated-name test | compression inside final-packet RDATA |
| UDP stub exchange | Partial | `DnsClient` with EDNS advertisement | loopback integration | response-source validation and retry policy |
| TCP fallback | Partial | TC retry and framing | loopback integration | persistent connection reuse and multiple outstanding queries |
| Positive cache | Partial | monotonic expiry | boundary tests | RRset-aware replacement and capacity eviction |
| Negative cache | Partial | SOA TTL/MINIMUM | NXDOMAIN test | NODATA cache key semantics and stale policy |
| Iterative resolver | Partial | referrals, CNAME, retries, subsidiary NS lookup, shared budgets | packet scenarios | cache integration and IPv6 subsidiary lookup |
| Bailiwick validation | Partial | accepts only in-zone glue | malicious additional scenario | sibling-zone cases |
| Authoritative exact answers | Partial | `Zone` | examples | multi-question policy documentation |
| Delegations and glue | Partial | closest NS cut | referral test | glue bailiwick validation at construction |
| Wildcards | Partial | closest-encloser synthesis | example | empty non-terminal and wildcard CNAME tables |
| UDP/TCP authoritative server | Partial | `DnsServer` with EDNS/legacy sizing | real sockets | overload response and observability hooks |
| EDNS(0) | Covered | OPT model, payload negotiation, extended RCODE, BADVERS, DO, unknown options | codec + socket scenarios | — |
| Zone-file loading | Planned | — | — | RFC 1035 presentation parser and validation diagnostics |
| Query/server CLI | Planned | — | — | commands, exit codes, human and JSON output |
| Fuzzing | Partial | arbitrary bounded ScalaCheck bytes | totality property | coverage-guided corpus and CI job |

## Book coverage

| Part | Status | Current material | Required expansion |
|---|---|---|---|
| Before DNS | Covered | model, binary primer, setup, roadmap, diagrams | keep terminology synchronized |
| Smallest working DNS | Planned | old short notes only | five runnable chapters and snapshots |
| Trustworthy wire codec | Partial | short topic notes | implementation-sized chapters and packet diagrams |
| Recursive resolver | Partial | cache overview | iterative scenario chapters and traces |
| Authoritative server | Partial | short policy overview | zone loading, server lifecycle, `dig` lab |
| Hardening | Partial | checklist | fuzz corpus, budgets, threat diagrams |
| Appendices | Partial | glossary | RFC index, fixture catalog, Scala feature index |

## Explicitly out of implementation scope

The book must still explain where these fit and link primary specifications:

| Feature | Primary specifications | Why separate |
|---|---|---|
| DNSSEC validation | RFC 4033, 4034, 4035 | cryptographic validation and trust-anchor lifecycle |
| Dynamic update | RFC 2136 | authentication, prerequisites, and durable zone mutation |
| AXFR and IXFR | RFC 5936, RFC 1995 | streaming transfer and secondary-server state |
| TSIG | RFC 8945 | shared-secret authentication and time synchronization |
| DNS over TLS | RFC 7858 | TLS policy and connection management |
| DNS over HTTPS | RFC 8484 | HTTP semantics and deployment policy |
| DNS over QUIC | RFC 9250 | QUIC transport and stream lifecycle |
| mDNS | RFC 6762 | multicast, probing, and link-local conflict rules |

## How completion is measured

CI passing is necessary but not sufficient. A row moves to Covered only in the
same change that adds its implementation, adversarial tests, chapter, and exact
RFC links. Reviewers should reject changes that update only the status label.
