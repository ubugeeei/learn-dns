package dns

class ZoneSuite extends munit.FunSuite:
  private val origin = DomainName.unsafe("example.com.")
  private val host = DomainName.unsafe("www.example.com.")
  private val soa = ResourceRecord(origin, RecordClass.IN, 300, RecordData.SOA(
    DomainName.unsafe("ns.example.com."), DomainName.unsafe("hostmaster.example.com."),
    1, 3600, 600, 86400, 300
  ))
  private val address = ResourceRecord(host, RecordClass.IN, 60, RecordData.ipv4("192.0.2.8"))
  private val zone = Zone.create(origin, soa, Vector(address)).toOption.get

  test("returns authoritative exact answers") {
    val response = zone.answer(query(host, RecordType.A))
    assert(response.flags.authoritative)
    assertEquals(response.flags.responseCode, ResponseCode.NoError)
    assertEquals(response.answers, Vector(address))
  }

  test("distinguishes NODATA from NXDOMAIN") {
    val noData = zone.answer(query(host, RecordType.AAAA))
    assertEquals(noData.flags.responseCode, ResponseCode.NoError)
    assertEquals(noData.authorities, Vector(soa))
    val missing = zone.answer(query(DomainName.unsafe("missing.example.com."), RecordType.A))
    assertEquals(missing.flags.responseCode, ResponseCode.NameError)
    assertEquals(missing.authorities, Vector(soa))
  }

  test("refuses names outside its authority") {
    assertEquals(zone.answer(query(DomainName.unsafe("example.net."), RecordType.A)).flags.responseCode, ResponseCode.Refused)
  }

  test("validates records when constructing the zone") {
    val outside = address.copy(name = DomainName.unsafe("example.net."))
    assertEquals(Zone.create(origin, soa, Vector(outside)), Left(Zone.Error.OutOfZone(outside.name)))
  }

  private def query(name: DomainName, kind: RecordType): Message =
    Message(42, questions = Vector(Question(name, kind)))
