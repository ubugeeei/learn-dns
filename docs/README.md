# chibidns: Build DNS from One Packet

This is a book about implementing the Domain Name System in Scala 3. We begin
with twelve bytes, keep the program runnable after every small change, and end
with a caching recursive resolver and an authoritative server.

The project has two equally important outputs:

- `src/` is the final, reusable implementation.
- `docs/` explains how to derive it without assuming DNS knowledge.

See [Coverage and Completion Contract](COVERAGE.md) for an honest feature-by-feature
status. A table-of-contents entry is not considered implemented by itself.

The approach is inspired by the small, continuously working milestones used by
the [chibivue book](https://book.chibivue.land/). The goal is not to paste a
finished parser. The goal is to understand why each byte, type, limit, and
boundary exists well enough to reimplement it yourself.

## Who this is for

You should be able to read basic Scala expressions, case classes, and tests. You
do **not** need to know DNS, binary protocols, networking, or advanced Scala 3.
Those concepts are introduced before they are used.

If Scala 3 is new to you, read the Scala notes in each chapter. They explain the
language feature locally, where its benefit is visible, instead of front-loading
a language tour.

## How to use the book

Each chapter follows the same loop:

1. Observe one real protocol behavior.
2. Draw or inspect the bytes involved.
3. Implement the smallest new type or function.
4. Add a normal test and an adversarial test.
5. Run the program before moving on.
6. Compare the result with the normative RFC text.

Commands are run from the repository root:

```console
sbt test
```

Tests are part of the explanation. Keep them open beside the chapter. A test
named `rejects a compression pointer cycle` is a runnable statement about the
protocol and not merely a regression check.

## Learning paths

### Minimal DNS

Read Parts 0 and 1. You will build and inspect a valid DNS query without sockets,
then send it over UDP. This gives a broad view quickly.

### Protocol implementer

Continue through Part 2. You will build the complete codec, including compressed
names and typed resource records, and learn to treat network bytes as hostile.

### Resolver implementer

Continue through Part 3. You will implement TTL caching, aliases, referrals,
bailiwick rules, and an iterative walk from a root server.

### Server implementer

Read Part 4. You will turn immutable zone data into UDP and TCP authoritative
answers and distinguish NODATA, NXDOMAIN, delegation, and wildcard synthesis.

## Table of contents

### Part 0 — Before DNS

1. [What problem DNS solves](00-introduction/01-what-is-dns.md)
2. [Read bytes without fear](00-introduction/02-binary-primer.md)
3. [Set up the Scala project](00-introduction/03-setup.md)
4. [Architecture and milestones](00-introduction/04-roadmap.md)

### Part 1 — The smallest working DNS

5. [Our first twelve bytes](01-minimal/01-twelve-bytes.md)
6. Add one question
7. Encode `example.com.`
8. Send the query over UDP
9. Decode one IPv4 answer
10. Minimal milestone review

### Part 2 — A trustworthy wire codec

11. Make invalid names unrepresentable
12. Unsigned integers on the JVM
13. Header flags as data
14. Questions and the four sections
15. Resource records and RDLENGTH
16. A and AAAA
17. Name-bearing records
18. TXT and unknown records
19. Compression pointers
20. Cycles, bounds, and parser budgets
21. Round trips and packet fixtures

### Part 3 — A recursive resolver

22. Separate transport from policy
23. UDP, truncation, and TCP retry
24. TTL and a monotonic cache
25. Negative caching
26. CNAME chains
27. Read a referral
28. [Root hints and iterative resolution](03-resolver/01-iterative-resolution.md)
29. Glue and bailiwick
30. Retry budgets and failure modes
31. Query-name minimization

### Part 4 — An authoritative server

32. Zones are not domain names
33. [Load and validate zone data](04-authoritative/01-zone-files.md)
34. Exact RRset answers
35. NODATA and NXDOMAIN
36. Delegations and glue
37. Wildcards
38. UDP and TCP listeners
39. Truncation and EDNS payload sizes
40. [Run and query the authoritative server](04-authoritative/02-run-the-server.md)

### Part 5 — Beyond the small implementation

41. Fuzzing the decoder
42. Cache poisoning and DNS Cookies
43. [EDNS](02-codec/10-edns.md)
44. Reading DNSSEC records
45. The DNSSEC chain of trust
46. Operational hardening
47. Where to read production resolver source

### Appendices

- Record-type cookbook
- Packet fixture catalog
- RFC-to-code index
- IANA registry workflow
- Scala 3 feature index
- [Glossary](glossary.md)

## What exists today

The final implementation currently includes validated names, common resource
records, compression-safe encoding and decoding, UDP-to-TCP stub transport, an
authoritative zone policy, and positive/negative caching. The book is being
expanded in the order above. A title without a link is an explicit upcoming
milestone, not a claim that the chapter already exists.

## Normative foundation

The two original specifications remain the starting point:

- [RFC 1034 — Concepts and Facilities](https://www.rfc-editor.org/rfc/rfc1034)
- [RFC 1035 — Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)

They have been updated by many later RFCs. Each chapter links the exact section
that governs the behavior being implemented; the appendix will also provide the
reverse mapping from an RFC requirement to source and tests.
