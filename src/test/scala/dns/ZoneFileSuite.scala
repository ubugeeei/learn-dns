package dns

class ZoneFileSuite extends munit.FunSuite:
  private val origin = DomainName.unsafe("example.test.")

  test("MASTER-FILE: loads directives, relative names, omitted owners, and common records") {
    val input =
      """
      |$ORIGIN example.test.
      |$TTL 1h
      |@ IN SOA ns1 hostmaster (
      |  2026071201  ; serial
      |  1h 15m 1w 5m
      |)
      |@       NS    ns1
      |@       MX 10 mail
      |ns1     A     192.0.2.53
      |www     A     192.0.2.80
      |        AAAA  2001:db8::80
      |alias   CNAME www
      |_dns._tcp SRV 0 5 53 ns1
      |message TXT "hello world" "second chunk"
      |""".stripMargin

    val zone = ZoneFile.parse(input, origin).toOption.get

    assertEquals(answer(zone, "www.example.test.", RecordType.A).answers.map(_.ttl), Vector(3600L))
    assertEquals(
      answer(zone, "www.example.test.", RecordType.AAAA).answers.map(_.data),
      Vector(RecordData.ipv6("2001:db8::80"))
    )
    assertEquals(
      answer(zone, "alias.example.test.", RecordType.A).answers.map(_.data),
      Vector(RecordData.CName(DomainName.unsafe("www.example.test.")))
    )
    assertEquals(
      answer(zone, "message.example.test.", RecordType.TXT).answers.map(_.data),
      Vector(
        RecordData.TXT(Vector("hello world".getBytes.toVector, "second chunk".getBytes.toVector))
      )
    )
  }

  test("MASTER-FILE-ESCAPE: decodes decimal and escaped punctuation in quoted TXT") {
    val input =
      minimumZone + """
      |escaped TXT "semi\;colon" "A\066C"
      |""".stripMargin

    val zone = ZoneFile.parse(input, origin).toOption.get

    assertEquals(
      answer(zone, "escaped.example.test.", RecordType.TXT).answers.map(_.data),
      Vector(RecordData.TXT(Vector("semi;colon".getBytes.toVector, "ABC".getBytes.toVector)))
    )
  }

  test("MASTER-FILE-DIAGNOSTICS: accumulates independent line failures") {
    val input =
      """
      |$TTL 1h
      |@ SOA ns hostmaster 1 1h 1h 1h 1h
      |bad A 999.2.3.4
      |other UNKNOWN value
      |""".stripMargin

    val diagnostics = ZoneFile.parse(input, origin).left.toOption.get

    assertEquals(diagnostics.map(_.line), Vector(4, 5))
    assert(diagnostics.exists(_.message.contains("IPv4")))
    assert(diagnostics.exists(_.message.contains("unsupported record type")))
  }

  test("MASTER-FILE-OWNER: rejects owner omission before the first record") {
    val input = "$TTL 60\n  A 192.0.2.1\n"

    assertEquals(
      ZoneFile.parse(input, origin),
      Left(Vector(ZoneFile.Diagnostic(2, "owner omitted before first record")))
    )
  }

  test("MASTER-FILE-LIMITS: rejects oversized input and record counts") {
    assertEquals(
      ZoneFile.parse("12345", origin, ZoneFile.Config(maxInputBytes = 4)),
      Left(Vector(ZoneFile.Diagnostic(1, "zone file exceeds 4 bytes")))
    )
    val diagnostics =
      ZoneFile.parse(
        minimumZone + "a A 192.0.2.1\nb A 192.0.2.2\n",
        origin,
        ZoneFile.Config(maxRecords = 2)
      ).left.toOption.get
    assert(diagnostics.exists(_.message.contains("record count exceeds 2")))
  }

  private val minimumZone =
    """
    |$ORIGIN example.test.
    |$TTL 1h
    |@ SOA ns hostmaster 1 1h 15m 1w 5m
    |@ NS ns
    |ns A 192.0.2.53
    |""".stripMargin

  private def answer(zone: Zone, owner: String, kind: RecordType): Message = zone
    .answer(Message(1, questions = Vector(Question(DomainName.unsafe(owner), kind))))
