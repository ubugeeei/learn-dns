package dns.cli

import dns.*
import java.nio.charset.StandardCharsets
import java.nio.file.Files

class CliSuite extends munit.FunSuite:
  test("QUERY-CLI: parses type, server, timeout, UDP size, and EDNS switch") {
    val config =
      DnsQuery.parse(Vector(
        "example.test",
        "AAAA",
        "--server",
        "[2001:db8::53]:5353",
        "--timeout-ms",
        "750",
        "--udp-size",
        "1400",
        "--no-edns"
      )).toOption.get

    assertEquals(config.name, DomainName.unsafe("example.test."))
    assertEquals(config.recordType, RecordType.AAAA)
    assertEquals(config.server.getAddress.getHostAddress, "2001:db8:0:0:0:0:0:53")
    assertEquals(config.server.getPort, 5353)
    assertEquals(config.timeout.toMillis, 750L)
    assertEquals(config.udpPayloadSize, 1400)
    assertEquals(config.enableEdns, false)
  }

  test("QUERY-CLI-DIAGNOSTICS: rejects unsupported types and invalid sizes") {
    assertEquals(
      DnsQuery.parse(Vector("example.test.", "NAPTR")),
      Left("unsupported query type: NAPTR")
    )
    assertEquals(
      DnsQuery.parse(Vector("example.test.", "--udp-size", "128")),
      Left("UDP size must be between 512 and 65535")
    )
  }

  test("SERVER-CLI: parses and loads a validated zone file") {
    val file = Files.createTempFile("learn-dns-zone", ".zone")
    try
      Files.writeString(file, minimumZone, StandardCharsets.UTF_8)
      val config =
        DnsServe.parse(Vector(
          file.toString,
          "example.test.",
          "--bind",
          "127.0.0.1",
          "--port",
          "0",
          "--udp-size",
          "1400"
        )).toOption.get

      val loaded = DnsServe.load(config).toOption.get

      assertEquals(loaded._1.port, 0)
      assertEquals(loaded._1.maxUdpResponseBytes, 1400)
      val response = loaded._2.answer(Message(
        1,
        questions = Vector(Question(DomainName.unsafe("www.example.test."), RecordType.A))
      ))
      assertEquals(response.answers.map(_.data), Vector(RecordData.ipv4("192.0.2.80")))
    finally Files.deleteIfExists(file): Unit
  }

  test("PRESENTATION: renders every section with stable headings") {
    val name = DomainName.unsafe("example.test.")
    val message = Message(
      id = 7,
      flags = Flags(response = true, authoritative = true),
      questions = Vector(Question(name, RecordType.A)),
      answers = Vector(ResourceRecord(name, RecordClass.IN, 60, RecordData.ipv4("192.0.2.1")))
    )

    val rendered = Presentation.message(message)

    assert(rendered.contains("status: NOERROR"))
    assert(rendered.contains(";; QUESTION SECTION:"))
    assert(rendered.contains(";; ANSWER SECTION:"))
    assert(rendered.contains("192.0.2.1"))
  }

  test("RECURSIVE-CLI: requires roots and parses IPv4 and IPv6 endpoints") {
    assertEquals(
      DnsRecurse.parse(Vector.empty),
      Left("at least one --root or --root-hints file is required")
    )

    val config =
      DnsRecurse.parse(Vector(
        "--root",
        "192.0.2.1",
        "--root",
        "[2001:db8::1]:5353",
        "--port",
        "0",
        "--udp-size",
        "1400"
      )).toOption.get

    assertEquals(config.roots.map(_.getPort), Vector(53, 5353))
    assertEquals(config.roots.map(_.getAddress.getAddress.length), Vector(4, 16))
    assertEquals(config.port, 0)
    assertEquals(config.maxUdpResponseBytes, 1400)
  }

  test("RECURSIVE-CLI-HINTS: loads a validated root hints file") {
    val file = Files.createTempFile("learn-dns-roots", ".hints")
    try
      Files.writeString(
        file,
        ". 60 NS A.ROOT-SERVERS.NET.\nA.ROOT-SERVERS.NET. 60 A 192.0.2.1\n",
        StandardCharsets.UTF_8
      )
      val config = DnsRecurse.parse(Vector("--root-hints", file.toString)).toOption.get

      val roots = DnsRecurse.loadRoots(config).toOption.get

      assertEquals(roots.map(_.getAddress.getHostAddress), Vector("192.0.2.1"))
    finally Files.deleteIfExists(file): Unit
  }

  private val minimumZone =
    """
    |$ORIGIN example.test.
    |$TTL 1h
    |@ SOA ns hostmaster 1 1h 15m 1w 5m
    |@ NS ns
    |ns A 192.0.2.53
    |www A 192.0.2.80
    |""".stripMargin
