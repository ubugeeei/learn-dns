package dns

class ZoneSuite extends munit.FunSuite:
  private val origin = DomainName.unsafe("example.com.")
  private val host = DomainName.unsafe("www.example.com.")
  private val soa = ResourceRecord(
    origin,
    RecordClass.IN,
    300,
    RecordData.SOA(
      DomainName.unsafe("ns.example.com."),
      DomainName.unsafe("hostmaster.example.com."),
      1,
      3600,
      600,
      86400,
      300
    )
  )
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
    assertEquals(
      zone.answer(query(DomainName.unsafe("example.net."), RecordType.A)).flags.responseCode,
      ResponseCode.Refused
    )
  }

  test("validates records when constructing the zone") {
    val outside = address.copy(name = DomainName.unsafe("example.net."))
    assertEquals(
      Zone.create(origin, soa, Vector(outside)),
      Left(Zone.Error.OutOfZone(outside.name))
    )
  }

  test("returns a non-authoritative referral with in-zone glue") {
    val child = DomainName.unsafe("child.example.com.")
    val nameServer = DomainName.unsafe("ns.child.example.com.")
    val delegation = ResourceRecord(child, RecordClass.IN, 3600, RecordData.NS(nameServer))
    val glue = ResourceRecord(nameServer, RecordClass.IN, 3600, RecordData.ipv4("192.0.2.53"))
    val delegated = Zone.create(origin, soa, Vector(delegation, glue)).toOption.get
    val response = delegated
      .answer(query(DomainName.unsafe("www.child.example.com."), RecordType.A))
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

  test("WILDCARD-EMPTY-NON-TERMINAL: an existing empty name produces NODATA") {
    val wildcard = ResourceRecord(
      DomainName.unsafe("*.example.com."),
      RecordClass.IN,
      60,
      RecordData.ipv4("192.0.2.9")
    )
    val descendant = ResourceRecord(
      DomainName.unsafe("host.branch.example.com."),
      RecordClass.IN,
      60,
      RecordData.ipv4("192.0.2.10")
    )
    val wildcardZone = Zone.create(origin, soa, Vector(wildcard, descendant)).toOption.get

    val response = wildcardZone
      .answer(query(DomainName.unsafe("branch.example.com."), RecordType.A))

    assertEquals(response.flags.responseCode, ResponseCode.NoError)
    assertEquals(response.answers, Vector.empty)
    assertEquals(response.authorities, Vector(soa))
  }

  test("QUESTION-COUNT: authoritative policy rejects zero or multiple questions") {
    assertEquals(zone.answer(Message(1)).flags.responseCode, ResponseCode.FormatError)
    assertEquals(
      zone.answer(Message(
        1,
        questions = Vector(Question(host, RecordType.A), Question(host, RecordType.AAAA))
      )).flags.responseCode,
      ResponseCode.FormatError
    )
  }

  test("CNAME-EXCLUSIVITY: zone validation rejects other data at a CNAME owner") {
    val cname = ResourceRecord(
      host,
      RecordClass.IN,
      60,
      RecordData.CName(DomainName.unsafe("target.example.com."))
    )

    assertEquals(
      Zone.create(origin, soa, Vector(address, cname)),
      Left(Zone.Error.CnameCoexists(host))
    )
  }

  test("SOA-UNIQUENESS: zone validation rejects an additional SOA") {
    assertEquals(
      Zone.create(origin, soa, Vector(soa.copy(ttl = 60))),
      Left(Zone.Error.MultipleSoa(2))
    )
  }

  private def query(name: DomainName, kind: RecordType): Message = Message(
    42,
    questions = Vector(Question(name, kind))
  )
