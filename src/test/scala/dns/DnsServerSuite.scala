package dns

import scala.concurrent.duration.*

class DnsServerSuite extends munit.FunSuite:
  private val origin = DomainName.unsafe("example.test.")
  private val host = DomainName.unsafe("www.example.test.")
  private val soa = ResourceRecord(
    origin,
    RecordClass.IN,
    300,
    RecordData.SOA(
      DomainName.unsafe("ns.example.test."),
      DomainName.unsafe("hostmaster.example.test."),
      1,
      3600,
      600,
      86400,
      300
    )
  )

  test("serves an authoritative answer over a real UDP socket") {
    val record = ResourceRecord(host, RecordClass.IN, 60, RecordData.ipv4("192.0.2.42"))
    val zone = Zone.create(origin, soa, Vector(record)).toOption.get
    val server = DnsServer.start(zone.answer)
    try
      val client = new DnsClient(server.address, 2.seconds)
      val response = client.query(host, RecordType.A).toOption.get
      assertEquals(response.answers, Vector(record))
      assert(response.flags.authoritative)
      assertEquals(server.metrics.answered, 1L)
    finally server.close()
  }

  test("truncated UDP responses are retried over TCP") {
    val records = (1 to 40).toVector.map { index =>
      ResourceRecord(
        host,
        RecordClass.IN,
        60,
        RecordData.TXT(Vector(s"payload-$index-${"x" * 24}".getBytes.toVector))
      )
    }
    val zone = Zone.create(origin, soa, records).toOption.get
    val config = DnsServer.Config(maxUdpResponseBytes = 512)
    val server = DnsServer.start(zone.answer, config)
    try
      val client = new DnsClient(server.address, 2.seconds)
      val response = client.query(host, RecordType.TXT).toOption.get
      assertEquals(response.answers, records)
      assert(server.metrics.received >= 2L)
    finally server.close()
  }

  test("EDNS-NEGOTIATION: advertises server size and honors the client UDP limit") {
    val records = (1 to 30).toVector.map { index =>
      ResourceRecord(
        host,
        RecordClass.IN,
        60,
        RecordData.TXT(Vector(s"record-$index-${"x" * 32}".getBytes.toVector))
      )
    }
    val zone = Zone.create(origin, soa, records).toOption.get
    val server = DnsServer.start(zone.answer, DnsServer.Config(maxUdpResponseBytes = 1400))
    try
      val client = new DnsClient(server.address, 2.seconds, udpPayloadSize = 700)
      val response = client.query(host, RecordType.TXT).toOption.get
      assertEquals(response.answers, records)
      assertEquals(
        response.additionals.flatMap(Edns.fromRecord).map(_.udpPayloadSize),
        Vector(1400)
      )
      assert(server.metrics.received >= 2L)
    finally server.close()
  }

  test("EDNS-BADVERS: reports unsupported versions through the extended RCODE") {
    val zone = Zone.create(origin, soa, Vector.empty).toOption.get
    val server = DnsServer.start(zone.answer)
    try
      val request = Message(
        id = 77,
        questions = Vector(Question(host, RecordType.A)),
        additionals = Vector(Edns(1232, version = 1).toRecord)
      )
      val response = udpExchange(server.address, request)
      val edns = response.additionals.headOption.flatMap(Edns.fromRecord)
      assertEquals(response.flags.responseCode, ResponseCode.NoError)
      assertEquals(edns.map(_.extendedResponseCode), Some(1))
      assertEquals(edns.map(_.version), Some(0))
      assertEquals(response.answers, Vector.empty)
    finally server.close()
  }

  test("malformed input receives FORMERR instead of killing the listener") {
    val zone = Zone.create(origin, soa, Vector.empty).toOption.get
    val server = DnsServer.start(zone.answer)
    try
      val socket = new java.net.DatagramSocket()
      socket.setSoTimeout(2000)
      val malformed = Array[Byte](0x12, 0x34, 0x01)
      socket.send(new java.net.DatagramPacket(malformed, malformed.length, server.address))
      val bytes = Array.ofDim[Byte](512)
      val response = new java.net.DatagramPacket(bytes, bytes.length)
      socket.receive(response)
      val decoded = MessageCodec.decode(bytes.slice(0, response.getLength)).toOption.get
      assertEquals(decoded.id, 0x1234)
      assertEquals(decoded.flags.responseCode, ResponseCode.FormatError)
      socket.close()
    finally server.close()
  }

  private def udpExchange(address: java.net.InetSocketAddress, request: Message): Message =
    val socket = new java.net.DatagramSocket()
    try
      socket.setSoTimeout(2000)
      val encoded = MessageCodec.encode(request)
      socket.send(new java.net.DatagramPacket(encoded, encoded.length, address))
      val bytes = Array.ofDim[Byte](4096)
      val packet = new java.net.DatagramPacket(bytes, bytes.length)
      socket.receive(packet)
      MessageCodec.decode(bytes.slice(0, packet.getLength)).toOption.get
    finally socket.close()
