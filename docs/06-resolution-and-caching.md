# 6. Resolution and Caching

Resolution and authoritative answering are different policies. A recursive
resolver follows referrals starting from root hints; an authoritative server
answers only from its zones. RFC 1034 §4.3.2 gives the canonical server algorithm.

A cache entry needs the record set and an absolute monotonic expiry. Never reset
TTL merely because an entry was read. Negative caching uses the zone SOA and the
rules in [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308). Cache keys include
name, type, and class; DNSSEC-aware implementations need more context.

An iterative resolver can be built step by step:

1. Seed root server addresses from a maintained root-hints file.
2. Query for the target and inspect answer, authority, and additional sections.
3. Follow CNAMEs with a strict depth/visited-name limit.
4. Select the closest NS referral and resolve missing glue safely.
5. Bound query count, referral depth, response size, and total deadline.
6. Cache RRsets using their smallest TTL.

Do not trust out-of-bailiwick additional records as glue. DNSSEC validation is a
separate chain-of-trust algorithm described by [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033),
[RFC 4034](https://www.rfc-editor.org/rfc/rfc4034), and [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035).

