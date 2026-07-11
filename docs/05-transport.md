# 5. UDP, TCP, and Truncation

DNS uses both UDP and TCP. A stub normally sends UDP, then retries the same query
over TCP when the response has the TC bit set. Modern requirements are specified
by [RFC 7766](https://www.rfc-editor.org/rfc/rfc7766); EDNS payload negotiation is
specified by [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891).

UDP carries a bare DNS message. TCP prefixes each message with an unsigned
two-octet length. A correct client must use exact-length reads, apply deadlines,
close sockets, and reject responses whose ID or echoed question differs.

`DnsClient` demonstrates a blocking boundary around the pure codec. Keeping I/O
here makes codec tests deterministic. For production, add source-address checks,
EDNS, randomized source ports, retry policy, cancellation, connection reuse, and
DNSSEC validation. The current client is deliberately a stub resolver: it asks
an upstream recursive server; it does not walk the root hierarchy itself.

