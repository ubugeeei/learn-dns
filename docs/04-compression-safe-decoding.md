# 4. Compression-Safe Decoding

DNS replaces repeated name suffixes with a two-octet pointer whose top bits are
`11` ([RFC 1035 §4.1.4](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4)).
A pointer changes where labels are read, but the enclosing cursor resumes just
after the pointer. This creates a graph traversal inside an otherwise linear
parser.

Use this algorithm:

1. Keep `scan`, the current label location, separate from the caller's cursor.
2. Save the first pointer's following offset as `resume`.
3. Track every visited offset and reject a repeated offset as a cycle.
4. Reject pointers and labels outside the packet.
5. Validate the assembled name's 63/255-octet invariants.
6. Move the caller to `resume`, or after the terminal zero when no pointer exists.

RFC 9267 catalogs real compression bugs and is essential security reading. Tests
should include self-pointers, multi-pointer cycles, out-of-bounds pointers,
reserved label tags, truncated labels, and excessive header counts.

The encoder records previously written suffix offsets below `0x4000`. RDATA is
buffered to calculate its length and therefore emitted uncompressed: offsets in
a temporary buffer are not offsets in the final packet.

