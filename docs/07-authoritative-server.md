# 7. An Authoritative Server

`Zone.create` validates that the SOA owns the origin, every record is in-zone,
and all records use the Internet class. Validation at construction keeps the hot
query path simple and total.

For one question, `Zone.answer` performs these practical steps:

1. Reject malformed, unsupported-class, and out-of-zone requests.
2. Find the exact owner name.
3. Return the requested RRset, or CNAME when present.
4. Return NOERROR plus SOA for an existing name without that type (NODATA).
5. Return NXDOMAIN plus SOA when the owner name does not exist.

NODATA and NXDOMAIN are different and have different cache semantics. RFC 2308
explains both. The SOA minimum/TTL controls negative caching.

To turn this policy into a daemon, place a small UDP/TCP listener around
`MessageCodec.decode`, `Zone.answer`, and `MessageCodec.encode`. Add response-size
truncation, concurrency limits, rate limiting, wildcard synthesis, referrals,
AXFR/IXFR, EDNS, and DNS Cookies before exposing it to untrusted networks.

