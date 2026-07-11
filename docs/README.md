# Implementing DNS from First Principles in Scala 3

This book grows a DNS implementation from bytes to a working network service.
Every chapter connects protocol rules to executable examples and tests.

1. [The DNS mental model](01-mental-model.md)
2. Domain names and wire primitives
3. Messages and resource records
4. Compression-safe decoding
5. UDP, TCP, and truncation
6. Resolution and caching
7. An authoritative server
8. Security, hardening, and next steps

The normative references are [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034)
and [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035). Later chapters link each
extension at the point where it becomes relevant.

