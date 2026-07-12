package dns

class CacheSuite extends munit.FunSuite:
  private final class ManualTicker(var nanos: Long = 0L) extends Ticker
  private val name = DomainName.unsafe("www.example.com.")
  private val question = Question(name, RecordType.A)

  test("positive entries use the smallest answer TTL") {
    val clock = new ManualTicker()
    val cache = new Cache(clock)
    val response = answer(Vector(address(30), address(10)))
    assert(cache.put(question, response))
    clock.nanos = 9_000_000_000L
    assertEquals(cache.get(question).toList.flatMap(_.answers.map(_.ttl)), List(21L, 1L))
    clock.nanos = 10_000_000_000L
    assertEquals(cache.get(question), None)
  }

  test("zero TTL answers are not cached") {
    val cache = new Cache(new ManualTicker())
    assert(!cache.put(question, answer(Vector(address(0)))))
    assertEquals(cache.size, 0)
  }

  test("negative TTL is the minimum of SOA TTL and MINIMUM") {
    val clock = new ManualTicker()
    val cache = new Cache(clock)
    val soa = ResourceRecord(
      DomainName.unsafe("example.com."),
      RecordClass.IN,
      600,
      RecordData.SOA(
        DomainName.unsafe("ns.example.com."),
        DomainName.unsafe("hostmaster.example.com."),
        1,
        3600,
        600,
        86400,
        120
      )
    )
    val response = answer(Vector.empty).copy(
      flags = Flags(response = true, responseCode = ResponseCode.NameError),
      authorities = Vector(soa)
    )
    assert(cache.put(question, response))
    clock.nanos = 119_000_000_000L
    assertEquals(cache.get(question).map(_.authorities.head.ttl), Some(1L))
    clock.nanos = 120_000_000_000L
    assertEquals(cache.get(question), None)
  }

  test("SERVFAIL is never cached") {
    val cache = new Cache(new ManualTicker())
    val response = answer(Vector(address(30)))
      .copy(flags = Flags(response = true, responseCode = ResponseCode.ServerFailure))
    assert(!cache.put(question, response))
  }

  test("NXDOMAIN applies to every type at the same name and class") {
    val cache = new Cache(new ManualTicker())
    val response = negative(ResponseCode.NameError)
    assert(cache.put(question, response))

    assert(cache.get(question.copy(recordType = RecordType.AAAA)).nonEmpty)
  }

  test("NODATA remains specific to the requested type") {
    val cache = new Cache(new ManualTicker())
    assert(cache.put(question, negative(ResponseCode.NoError)))

    assertEquals(cache.get(question.copy(recordType = RecordType.AAAA)), None)
  }

  test("capacity evicts the entry with the earliest expiry") {
    val cache = new Cache(new ManualTicker(), maxEntries = 2)
    val first = question.copy(name = DomainName.unsafe("first.example.com."))
    val second = question.copy(name = DomainName.unsafe("second.example.com."))
    val third = question.copy(name = DomainName.unsafe("third.example.com."))

    assert(cache.put(first, answer(Vector(address(10).copy(name = first.name)))))
    assert(cache.put(second, answer(Vector(address(30).copy(name = second.name)))))
    assert(cache.put(third, answer(Vector(address(20).copy(name = third.name)))))

    assertEquals(cache.get(first), None)
    assert(cache.get(second).nonEmpty)
    assert(cache.get(third).nonEmpty)
    assertEquals(cache.size, 2)
  }

  private def negative(code: ResponseCode): Message =
    val soa = ResourceRecord(
      DomainName.unsafe("example.com."),
      RecordClass.IN,
      60,
      RecordData.SOA(
        DomainName.unsafe("ns.example.com."),
        DomainName.unsafe("hostmaster.example.com."),
        1,
        3600,
        600,
        86400,
        60
      )
    )
    answer(Vector.empty)
      .copy(flags = Flags(response = true, responseCode = code), authorities = Vector(soa))

  private def address(ttl: Long): ResourceRecord = ResourceRecord(
    name,
    RecordClass.IN,
    ttl,
    RecordData.ipv4("192.0.2.1")
  )

  private def answer(records: Vector[ResourceRecord]): Message = Message(
    1,
    Flags(response = true),
    Vector(question),
    answers = records
  )
