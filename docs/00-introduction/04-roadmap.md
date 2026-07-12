# Architecture and Runnable Milestones

Building every DNS feature before running anything would leave us with weeks of
uncertain code. Instead, each milestone is a useful program with a deliberately
small limitation. The next milestone removes one limitation without discarding
the concepts learned in the previous one.

## The dependency direction

```text
application / CLI
       |
resolver policy        authoritative policy
       |                         |
       +-----------+-------------+
                   |
             transport boundary
                   |
              message codec
                   |
          domain and record model
                   |
              bytes / sockets
```

Arrows point toward dependencies. The model knows nothing about sockets. The
codec knows nothing about caching. Resolver and server policy can therefore be
tested with in-memory messages.

## Milestone 0: inspect twelve bytes

Input: a fixed DNS header as hexadecimal bytes.

Output: its ID, flags, and four section counts.

What it teaches: unsigned network-order integers and the packet skeleton.

What it cannot do: names, questions, records, or networking.

## Milestone 1: encode one A question

Input: `example.com.`.

Output: a valid query packet whose bytes match a fixture.

What it teaches: label encoding, the root terminator, type, and class.

Temporary limitation: names are uncompressed and presentation parsing is ASCII.

## Milestone 2: ask a local UDP server

Input: the query from milestone 1.

Output: raw response bytes and a decoded IPv4 answer.

What it teaches: datagrams, deadlines, transaction IDs, and response validation.

Temporary limitation: only A records and UDP responses that fit one datagram.

## Milestone 3: complete the safe codec

Input: arbitrary DNS message bytes.

Output: a typed `Message` or a structured `DecodeError`.

What it teaches: ADTs, bounded cursors, RDLENGTH, compression graphs, and parser
budgets. This is the foundation already represented by `MessageCodec`.

## Milestone 4: cache an upstream resolver

Input: repeated client questions.

Output: upstream answers on a miss and decreasing-TTL cached answers on a hit.

What it teaches: monotonic time, positive and negative caching, and separation
of transport from policy. `Cache` and `CachingResolver` implement this stage.

## Milestone 5: walk from a root

Input: a name, root hints, and a query budget.

Output: a final answer found by following referrals.

What it teaches: NS RRsets, glue, bailiwick, CNAME chains, retries, and loops.

This is where the project becomes an iterative resolver rather than a stub that
delegates recursion to another service.

## Milestone 6: serve one authoritative zone

Input: validated zone records and client queries.

Output: exact answers, CNAMEs, NODATA, and NXDOMAIN over UDP and TCP.

What it teaches: zone cuts, authoritative policy, negative answers, wildcard
synthesis, truncation, and concurrent server lifecycles.

## Milestone 7: harden the boundaries

Input: malformed packets, slow peers, and randomized byte streams.

Output: bounded errors without hangs, crashes, or unbounded allocation.

What it teaches: fuzzing, resource budgets, rate limits, cache poisoning
defenses, EDNS negotiation, and the boundary of our educational implementation.

## Why the final source is not copied into every chapter

The book will retain runnable milestone snapshots under `docs/impls`. Each is an
independent sbt project and intentionally contains only the code introduced up
to that point. The root `src` remains the final implementation.

This duplication is useful in a teaching repository: a reader at milestone 2
should not need to mentally subtract caching, DNSSEC records, and server policy
from a final codebase. Snapshot creation is part of each milestone's definition
of done, not an appendix chore postponed until the end.

## Definition of done for a chapter

A chapter is complete only when it contains:

- a concrete observable goal;
- prerequisite concepts explained locally;
- implementation in small compilable steps;
- the complete result or a link to its snapshot;
- at least one happy-path and one adversarial test;
- a “why this design?” section;
- exact normative specification links;
- exercises with expected behavior;
- a checkpoint stating the remaining limitations.

This prevents short architecture notes from masquerading as implementation
chapters. It also gives contributors an objective review checklist.
