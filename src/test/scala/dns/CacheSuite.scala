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
    val soa = ResourceRecord(DomainName.unsafe("example.com."), RecordClass.IN, 600,
      RecordData.SOA(DomainName.unsafe("ns.example.com."), DomainName.unsafe("hostmaster.example.com."),
        1, 3600, 600, 86400, 120))
    val response = answer(Vector.empty).copy(
      flags = Flags(response = true, responseCode = ResponseCode.NameError), authorities = Vector(soa))
    assert(cache.put(question, response))
    clock.nanos = 119_000_000_000L
    assertEquals(cache.get(question).map(_.authorities.head.ttl), Some(481L))
    clock.nanos = 120_000_000_000L
    assertEquals(cache.get(question), None)
  }

  test("SERVFAIL is never cached") {
    val cache = new Cache(new ManualTicker())
    val response = answer(Vector(address(30))).copy(
      flags = Flags(response = true, responseCode = ResponseCode.ServerFailure))
    assert(!cache.put(question, response))
  }

  private def address(ttl: Long): ResourceRecord =
    ResourceRecord(name, RecordClass.IN, ttl, RecordData.ipv4("192.0.2.1"))

  private def answer(records: Vector[ResourceRecord]): Message =
    Message(1, Flags(response = true), Vector(question), answers = records)

