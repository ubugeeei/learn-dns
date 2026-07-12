package dns

class RootHintsSuite extends munit.FunSuite:
  test("ROOT-HINTS: extracts addresses only for advertised root servers") {
    val hints =
      RootHints.parse("""
      |. 3600000 IN NS A.ROOT-SERVERS.NET.
      |. 3600000 IN NS B.ROOT-SERVERS.NET.
      |A.ROOT-SERVERS.NET. 3600000 A 198.41.0.4
      |A.ROOT-SERVERS.NET. 3600000 AAAA 2001:503:ba3e::2:30
      |B.ROOT-SERVERS.NET. 3600000 A 170.247.170.2
      |UNRELATED.EXAMPLE. 3600000 A 192.0.2.66
      |""".stripMargin).toOption.get

    assertEquals(
      hints.nameServers,
      Vector(DomainName.unsafe("A.ROOT-SERVERS.NET."), DomainName.unsafe("B.ROOT-SERVERS.NET."))
    )
    assertEquals(hints.addresses.map(_.getAddress.getAddress.length), Vector(4, 16, 4))
    assert(!hints.addresses.exists(_.getAddress.getHostAddress == "192.0.2.66"))
  }

  test("ROOT-HINTS-VALIDATION: requires root NS records and matching addresses") {
    assertEquals(
      RootHints.parse("unrelated. 60 A 192.0.2.1"),
      Left(RootHints.Error.MissingRootNameServers)
    )

    val server = DomainName.unsafe("A.ROOT-SERVERS.NET.")
    assertEquals(
      RootHints.parse(". 60 NS A.ROOT-SERVERS.NET."),
      Left(RootHints.Error.MissingAddresses(Vector(server)))
    )
  }
