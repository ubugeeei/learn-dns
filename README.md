# learn-dns

An educational, dependency-light DNS implementation in Scala 3. It pairs a
usable protocol library with a step-by-step book in [`docs`](docs/README.md).

## Build

Requirements: JDK 21 and sbt 1.11 or newer.

```console
sbt test
```

The implementation follows the IETF specifications linked from its Scaladoc
and from the book. It is intended for learning, experiments, and small local
services; it is not a hardened replacement for a production recursive resolver.

