package dns

class MessageCodecSuite extends munit.FunSuite:
  private val example = DomainName.unsafe("example.com.")

  test("decodes the RFC-style query wire layout") {
    val packet = hex("123401000001000000000000076578616d706c6503636f6d0000010001")
    val message = MessageCodec.decode(packet).toOption.get
    assertEquals(message.id, 0x1234)
    assertEquals(message.flags.recursionDesired, true)
    assertEquals(message.questions, Vector(Question(example, RecordType.A)))
  }

  test("round trips common resource record data") {
    val records = Vector(
      ResourceRecord(example, RecordClass.IN, 300, RecordData.ipv4("192.0.2.1")),
      ResourceRecord(example, RecordClass.IN, 300, RecordData.ipv6("2001:db8::1")),
      ResourceRecord(
        example,
        RecordClass.IN,
        60,
        RecordData.MX(10, DomainName.unsafe("mail.example.com."))
      ),
      ResourceRecord(
        example,
        RecordClass.IN,
        60,
        RecordData.TXT(Vector("hello".getBytes.toVector))
      ),
      ResourceRecord(
        example,
        RecordClass.IN,
        60,
        RecordData.SRV(0, 5, 443, DomainName.unsafe("service.example.com."))
      )
    )
    val original = Message(
      7,
      Flags(response = true, authoritative = true),
      Vector(Question(example, RecordType.A)),
      records
    )
    assertEquals(MessageCodec.decode(MessageCodec.encode(original)), Right(original))
  }

  test("encoder compresses repeated owner names") {
    val message = Message(
      1,
      questions = Vector(Question(example, RecordType.A)),
      answers = Vector(ResourceRecord(example, RecordClass.IN, 30, RecordData.ipv4("192.0.2.1")))
    )
    val encoded = MessageCodec.encode(message)
    assert(encoded.sliding(2).exists(_.sameElements(Array(0xc0.toByte, 0x0c.toByte))))
    assertEquals(MessageCodec.decode(encoded), Right(message))
  }

  test("rejects a compression pointer cycle") {
    val packet = hex("000001000001000000000000c00c00010001")
    assertEquals(MessageCodec.decode(packet), Left(DecodeError.CompressionLoop(12)))
  }

  test("rejects pointer beyond the packet") {
    val packet = hex("000001000001000000000000c0ff00010001")
    assertEquals(
      MessageCodec.decode(packet),
      Left(DecodeError.CompressionPointerOutOfBounds(255, 18))
    )
  }

  test("COMPRESSION-BUDGET: rejects a long acyclic pointer chain") {
    val pointerCount = NameCodec.MaxPointerJumps + 1
    val packet = Array.ofDim[Byte](pointerCount * 2 + 1)
    (0 until pointerCount).foreach { index =>
      val target = (index + 1) * 2
      packet(index * 2) = (0xc0 | (target >>> 8)).toByte
      packet(index * 2 + 1) = target.toByte
    }

    assertEquals(
      NameCodec.decode(new WireCursor(packet)),
      Left(DecodeError.CompressionPointerLimit(NameCodec.MaxPointerJumps))
    )
  }

  test("rejects truncated and trailing messages") {
    assert(MessageCodec.decode(Array.fill(11)(0.toByte)).isLeft)
    val query = hex("123401000001000000000000076578616d706c6503636f6d0000010001") ++ Array(0.toByte)
    assertEquals(MessageCodec.decode(query), Left(DecodeError.TrailingBytes(1)))
  }

  test("enforces configurable section count limits before looping") {
    val packet = hex("000001000002000000000000")
    assertEquals(
      MessageCodec.decode(packet, sectionLimit = 1),
      Left(DecodeError.CountLimit("question", 2, 1))
    )
  }

  test("EDNS-ROUNDTRIP: preserves size, DO bit, version, and unknown options") {
    val edns = Edns(
      udpPayloadSize = 1232,
      extendedResponseCode = 2,
      dnssecOk = true,
      options = Vector(EdnsOption(65001, Vector[Byte](1, 2, 3)))
    )
    val message = Message(1, additionals = Vector(edns.toRecord))

    val decoded = MessageCodec.decode(MessageCodec.encode(message)).toOption.get

    assertEquals(decoded, message)
    assertEquals(decoded.additionals.headOption.flatMap(Edns.fromRecord), Some(edns))
  }

  test("EDNS-OPTION-LENGTH: rejects an option beyond RDLENGTH") {
    val packet = hex("00008000000000000000000100002904d000000000000400010001")

    assertEquals(
      MessageCodec.decode(packet),
      Left(DecodeError.InvalidRData(RecordType.OPT, "option exceeds RDLENGTH"))
    )
  }

  test("ENCODER-BOUNDS: rejects TXT chunks that cannot fit their length octet") {
    val message = Message(
      1,
      answers = Vector(ResourceRecord(
        example,
        RecordClass.IN,
        60,
        RecordData.TXT(Vector(Vector.fill(256)(0.toByte)))
      ))
    )

    assertEquals(MessageCodec.encodeValidated(message), Left(EncodeError.TxtChunkTooLong(256)))
  }

  test("ENCODER-BOUNDS: rejects unknown RDATA beyond unsigned 16-bit RDLENGTH") {
    val message = Message(
      1,
      answers = Vector(ResourceRecord(
        example,
        RecordClass.IN,
        60,
        RecordData.Unknown(RecordType.Unknown(65000), Vector.fill(65536)(0.toByte))
      ))
    )

    assertEquals(
      MessageCodec.encodeValidated(message),
      Left(EncodeError.RDataTooLong(RecordType.Unknown(65000), 65536))
    )
  }

  private def hex(value: String): Array[Byte] =
    value.grouped(2).map(Integer.parseInt(_, 16).toByte).toArray
