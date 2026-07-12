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

  test("returns a non-authoritative referral with in-zone glue") {
    val child = DomainName.unsafe("child.example.com.")
    val nameServer = DomainName.unsafe("ns.child.example.com.")
    val delegation = ResourceRecord(child, RecordClass.IN, 3600, RecordData.NS(nameServer))
    val glue = ResourceRecord(nameServer, RecordClass.IN, 3600, RecordData.ipv4("192.0.2.53"))
    val delegated = Zone.create(origin, soa, Vector(delegation, glue)).toOption.get
    val response = delegated.answer(query(DomainName.unsafe("www.child.example.com."), RecordType.A))
    assert(!response.flags.authoritative)
    assertEquals(response.authorities, Vector(delegation))
    assertEquals(response.additionals, Vector(glue))
  }

  test("synthesizes an owner name from the closest wildcard") {
    val wildcardName = DomainName.unsafe("*.example.com.")
    val wildcard = ResourceRecord(wildcardName, RecordClass.IN, 60, RecordData.ipv4("192.0.2.9"))
    val wildcardZone = Zone.create(origin, soa, Vector(wildcard)).toOption.get
    val requested = DomainName.unsafe("missing.example.com.")
    val response = wildcardZone.answer(query(requested, RecordType.A))
    assertEquals(response.answers, Vector(wildcard.copy(name = requested)))
  }

  private def query(name: DomainName, kind: RecordType): Message =
    Message(42, questions = Vector(Question(name, kind)))
