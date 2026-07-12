# learn-dns

An educational, dependency-light DNS implementation in Scala 3. It pairs a
usable protocol library with a step-by-step book in [`docs`](docs/README.md).

## Build

Requirements: JDK 21 and sbt 1.11 or newer.

```console
sbt test
```

Query an upstream server:

```console
sbt 'runMain dns.cli.DnsQuery example.com. A --server 1.1.1.1'
```

Serve a validated master file on UDP and TCP port 5353:

```console
sbt 'runMain dns.cli.DnsServe ./example.zone example.test. --port 5353'
```

Run a caching iterative resolver from explicitly configured root servers:

```console
sbt 'runMain dns.cli.DnsRecurse --root 198.41.0.4 --port 5353'
```

The implementation follows the IETF specifications linked from its Scaladoc
and from the book. It is intended for learning, experiments, and small local
services; it is not a hardened replacement for a production recursive resolver.
