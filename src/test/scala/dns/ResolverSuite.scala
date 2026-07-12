package dns

class ResolverSuite extends munit.FunSuite:
  private val name = DomainName.unsafe("example.com.")
  private val question = Question(name, RecordType.A)

  test("a cache hit avoids upstream I/O and adapts transaction metadata") {
    val cache = new Cache(() => 0L)
    val stored = Message(1, Flags(response = true), Vector(question),
      Vector(ResourceRecord(name, RecordClass.IN, 60, RecordData.ipv4("192.0.2.1"))))
    cache.put(question, stored)
    var calls = 0
    val upstream = new Exchange[[value] =>> Either[DnsClient.Error, value]]:
      def apply(request: Message): Either[DnsClient.Error, Message] =
        calls += 1
        Right(request)
    val result = new CachingResolver(cache, upstream).resolve(
      Message(99, Flags(recursionDesired = false), Vector(question)))
    assertEquals(calls, 0)
    assertEquals(result.toOption.map(_.id), Some(99))
    assertEquals(result.toOption.map(_.flags.recursionDesired), Some(false))
  }

  test("a miss delegates and stores the response") {
    val cache = new Cache(() => 0L)
    val response = Message(7, Flags(response = true), Vector(question),
      Vector(ResourceRecord(name, RecordClass.IN, 60, RecordData.ipv4("192.0.2.7"))))
    val upstream = new Exchange[[value] =>> Either[DnsClient.Error, value]]:
      def apply(request: Message): Either[DnsClient.Error, Message] = Right(response)
    assertEquals(new CachingResolver(cache, upstream).resolve(Message(7, questions = Vector(question))), Right(response))
    assertEquals(cache.size, 1)
  }
