# 1. The DNS Mental Model

DNS is a distributed, hierarchical database. A client asks a question made of
a domain name, a record type, and a class. A server returns zero or more typed
records plus metadata describing how the answer was produced.

## Start with the hierarchy

Read a name from right to left. In `www.example.com.` the final dot is the root,
`com` is below the root, `example` is below `com`, and `www` is below `example`.
Each delegation transfers authority for a subtree called a *zone*. This model is
specified in [RFC 1034 §3.1](https://www.rfc-editor.org/rfc/rfc1034#section-3.1).

The trailing dot matters: it says the name is absolute. Our Scala model stores
names as labels and always treats them as absolute, preventing accidental search
suffix expansion inside the protocol layer.

## Separate the layers

A practical implementation has four layers:

1. **Model** — valid names, questions, records, and message flags.
2. **Codec** — a total boundary from untrusted bytes to the model and back.
3. **Transport** — UDP first, TCP when a response is truncated.
4. **Policy** — caching, recursion, and authoritative zone behavior.

Keeping policy out of the codec is a security feature: parsing the same packet
must not depend on whether the caller is a client or a server.

## Follow one lookup

For an `A` lookup of `www.example.com.` a stub resolver sends one question to a
recursive resolver. The resolver may query a root server, a `com` server, then
an `example.com` server. It caches referrals and the final address for their TTLs
and returns the answer. [RFC 1034 §4.3.2](https://www.rfc-editor.org/rfc/rfc1034#section-4.3.2)
defines the server-side algorithm.

In the next chapter we turn the most constrained object—the domain name—into a
type that cannot represent malformed wire labels.
