# 3. Messages and Resource Records

A DNS message has a 12-byte header followed by question, answer, authority, and
additional sections ([RFC 1035 §4.1](https://www.rfc-editor.org/rfc/rfc1035#section-4.1)).
The header contains an ID, bit-packed flags, and four unsigned counts.

Scala enums model closed known values while `Unknown(code)` preserves registry
extensions. `RecordData` is an algebraic data type: pattern matching must handle
every supported RDATA shape, and unknown RDATA remains lossless. `ResourceRecord`
derives its type from its data, preventing an `A` type paired with MX bytes.

When adding a record type:

1. Add its IANA numeric value to `RecordType`.
2. Add a typed `RecordData` case.
3. Decode exactly `RDLENGTH` octets.
4. Encode the same case and add a round-trip test.

The current core supports A, AAAA, NS, CNAME, PTR, MX, TXT, SOA, and SRV. Type
codes are allocated in the [IANA DNS Parameters registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml).

