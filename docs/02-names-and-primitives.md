# 2. Names and Wire Primitives

RFC 1035 encodes a name as length-prefixed labels followed by a zero octet. The
name `www.example.com.` is `03 www 07 example 03 com 00`. Labels are at most 63
octets and the full uncompressed name at most 255 octets
([RFC 1035 §2.3.4](https://www.rfc-editor.org/rfc/rfc1035#section-2.3.4)).

`DomainName` stores `Vector[Vector[Byte]]`, not `String`: DNS labels are octets,
while Unicode belongs to an IDNA presentation layer. Its private constructor
makes validation unavoidable. Equality folds ASCII letters because DNS case is
insensitive ([RFC 4343](https://www.rfc-editor.org/rfc/rfc4343)).

Implement this layer first:

1. Split presentation input into labels.
2. Reject empty, overlong, and non-ASCII labels.
3. calculate `1 + Σ(1 + label.length)` and enforce 255.
4. Test root, boundaries, case equality, and malformed input.

`WireCursor` then centralizes bounds checks for unsigned 8-, 16-, and 32-bit
network-order fields. Returning `Either[DecodeError, A]` makes truncated input a
normal result rather than an exception escaping from deep parser code.

