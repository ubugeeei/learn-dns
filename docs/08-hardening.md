# 8. Hardening and Next Steps

Protocol correctness is necessary but not operational security. Keep every input
limit explicit: packet bytes, section counts, compression hops, CNAME depth,
referrals, outstanding work, and deadlines. Fuzz `MessageCodec.decode`; it should
return `Left`, never hang or throw, for arbitrary bytes.

Recommended implementation exercises, in order:

1. Add property tests asserting `decode(encode(message)) == message`.
2. Add EDNS OPT modeling and advertised UDP payload size.
3. Add a monotonic TTL cache and RFC 2308 negative entries.
4. Build an iterative resolver with bailiwick checking.
5. Add a UDP/TCP authoritative listener and integration tests.
6. Add DNSSEC record codecs, then validation as a separate policy layer.

Useful specifications include [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891)
for EDNS, [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766) for TCP,
[RFC 7873](https://www.rfc-editor.org/rfc/rfc7873) for DNS Cookies, and
[RFC 9156](https://www.rfc-editor.org/rfc/rfc9156) for query-name minimization.

The key architectural lesson is colocation: protocol invariants live beside the
types they protect, wire errors beside the cursor, compression beside name I/O,
and authoritative policy beside the validated zone. Network effects remain at
the outer edge.
