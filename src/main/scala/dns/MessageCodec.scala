package dns

import java.net.{ Inet4Address, Inet6Address, InetAddress }

/**
 * Encoder and total decoder for DNS messages defined by RFC 1035 §4.1.
 *
 * The default section limit prevents a tiny packet from forcing very large allocations or loops
 * through malicious header counts.
 */
object MessageCodec:
  val DefaultSectionLimit = 4096
  val MaxWireMessageBytes = 65535

  def decode(
      bytes: Array[Byte],
      sectionLimit: Int = DefaultSectionLimit
  ): Either[DecodeError, Message] =
    val cursor = new WireCursor(bytes)
    for
      id <- cursor.u16()
      bits <- cursor.u16()
      qd <- cursor.u16()
      an <- cursor.u16()
      ns <- cursor.u16()
      ar <- cursor.u16()
      _ <- validateCount("question", qd, sectionLimit)
      _ <- validateCount("answer", an, sectionLimit)
      _ <- validateCount("authority", ns, sectionLimit)
      _ <- validateCount("additional", ar, sectionLimit)
      questions <- repeat(qd)(decodeQuestion(cursor))
      answers <- repeat(an)(decodeRecord(cursor))
      authorities <- repeat(ns)(decodeRecord(cursor))
      additionals <- repeat(ar)(decodeRecord(cursor))
      _ <- Either.cond(cursor.remaining == 0, (), DecodeError.TrailingBytes(cursor.remaining))
    yield Message(id, decodeFlags(bits), questions, answers, authorities, additionals)

  /** Encodes a message after proving all length/count fields fit on the wire. */
  def encodeValidated(message: Message): Either[EncodeError, Array[Byte]] = validateForEncoding(
    message
  ).map(_ => encodeUnchecked(message))

  /**
   * Encodes an already trusted message or throws when its model exceeds wire limits.
   *
   * Network boundaries should prefer [[encodeValidated]]. This convenience API keeps packet
   * fixtures concise while never silently wrapping a length field.
   */
  def encode(message: Message): Array[Byte] = encodeValidated(message).fold(
    error => throw new IllegalArgumentException(s"message cannot be encoded: $error"),
    identity
  )

  private def encodeUnchecked(message: Message): Array[Byte] =
    val writer = new WireWriter()
    val names = new NameCodec.Encoder(writer)
    writer.u16(message.id)
    writer.u16(encodeFlags(message.flags))
    Vector(
      message.questions.size,
      message.answers.size,
      message.authorities.size,
      message.additionals.size
    ).foreach(writer.u16)
    message.questions.foreach { question =>
      names.write(question.name); writer.u16(question.recordType.code);
      writer.u16(question.recordClass.code)
    }
    (message.answers ++ message.authorities ++ message.additionals)
      .foreach(writeRecord(writer, names, _))
    writer.result()

  private def validateForEncoding(message: Message): Either[EncodeError, Unit] =
    val sections = Vector(
      "question" -> message.questions.size,
      "answer" -> message.answers.size,
      "authority" -> message.authorities.size,
      "additional" -> message.additionals.size
    )
    sections.find(_._2 > 0xffff) match
      case Some((name, count)) => Left(EncodeError.SectionCount(name, count))
      case None                =>
        val records = message.answers ++ message.authorities ++ message.additionals
        records.iterator.map(validateRecord).collectFirst { case Left(error) => Left(error) }
          .getOrElse {
            val questionBytes =
              message.questions.iterator.map(question => question.name.wireLength.toLong + 4).sum
            val recordBytes =
              records.iterator
                .map(record => record.name.wireLength.toLong + 10 + rdataLength(record.data)).sum
            val estimated = 12L + questionBytes + recordBytes
            Either.cond(
              estimated <= MaxWireMessageBytes,
              (),
              EncodeError.MessageTooLong(estimated, MaxWireMessageBytes)
            )
          }

  private def validateRecord(record: ResourceRecord): Either[EncodeError, Unit] =
    record.data match
      case RecordData.TXT(chunks) =>
        chunks.find(_.size > 255) match
          case Some(chunk) => Left(EncodeError.TxtChunkTooLong(chunk.size))
          case None        =>
            val length = rdataLength(record.data)
            Either.cond(length <= 0xffff, (), EncodeError.RDataTooLong(record.recordType, length))
      case data =>
        val length = rdataLength(data)
        Either.cond(length <= 0xffff, (), EncodeError.RDataTooLong(record.recordType, length))

  private def rdataLength(data: RecordData): Long =
    data match
      case _: RecordData.A            => 4
      case _: RecordData.AAAA         => 16
      case RecordData.NS(name)        => name.wireLength
      case RecordData.CName(name)     => name.wireLength
      case RecordData.Ptr(name)       => name.wireLength
      case RecordData.MX(_, exchange) => 2L + exchange.wireLength
      case RecordData.TXT(chunks)     => chunks.iterator.map(_.size.toLong + 1).sum
      case RecordData.SOA(primary, mailbox, _, _, _, _, _) =>
        primary.wireLength.toLong + mailbox.wireLength + 20
      case RecordData.SRV(_, _, _, target) => 6L + target.wireLength
      case RecordData.OPT(options)         =>
        options.iterator.map(option => option.data.size.toLong + 4).sum
      case RecordData.Unknown(_, bytes) => bytes.size.toLong

  private def decodeQuestion(cursor: WireCursor): Either[DecodeError, Question] =
    for name <- NameCodec.decode(cursor); kind <- cursor.u16(); cls <- cursor.u16()
    yield Question(name, RecordType.fromInt(kind), RecordClass.fromInt(cls))

  private def decodeRecord(cursor: WireCursor): Either[DecodeError, ResourceRecord] =
    for
      name <- NameCodec.decode(cursor)
      kindCode <- cursor.u16()
      classCode <- cursor.u16()
      ttl <- cursor.u32()
      length <- cursor.u16()
      end = cursor.offset + length
      _ <- Either
        .cond(end <= cursor.bytes.length, (), DecodeError.UnexpectedEnd(end, cursor.bytes.length))
      kind = RecordType.fromInt(kindCode)
      data <- decodeData(cursor, kind, length)
      _ <- Either
        .cond(cursor.offset == end, (), DecodeError.TrailingRData(kind, end - cursor.offset))
    yield ResourceRecord(name, RecordClass.fromInt(classCode), ttl, data)

  private def decodeData(
      cursor: WireCursor,
      kind: RecordType,
      length: Int
  ): Either[DecodeError, RecordData] =
    def address(expected: Int): Either[DecodeError, Array[Byte]] =
      if length != expected then
        Left(DecodeError.InvalidRData(kind, s"expected $expected octets, got $length"))
      else cursor.take(length).map(_.toArray)
    def name: Either[DecodeError, DomainName] = NameCodec.decode(cursor)
    kind match
      case RecordType.A =>
        address(4)
          .map(value => RecordData.A(InetAddress.getByAddress(value).asInstanceOf[Inet4Address]))
      case RecordType.AAAA =>
        address(16)
          .map(value => RecordData.AAAA(InetAddress.getByAddress(value).asInstanceOf[Inet6Address]))
      case RecordType.NS    => name.map(RecordData.NS.apply)
      case RecordType.CNAME => name.map(RecordData.CName.apply)
      case RecordType.PTR   => name.map(RecordData.Ptr.apply)
      case RecordType.MX    =>
        for preference <- cursor.u16(); exchange <- name yield RecordData.MX(preference, exchange)
      case RecordType.SOA =>
        for
          primary <- name; mailbox <- name; serial <- cursor.u32(); refresh <- cursor.u32()
          retry <- cursor.u32(); expire <- cursor.u32(); minimum <- cursor.u32()
        yield RecordData.SOA(primary, mailbox, serial, refresh, retry, expire, minimum)
      case RecordType.SRV =>
        for priority <- cursor.u16(); weight <- cursor.u16(); port <- cursor.u16(); target <- name
        yield RecordData.SRV(priority, weight, port, target)
      case RecordType.TXT => decodeTxt(cursor, length).map(RecordData.TXT.apply)
      case RecordType.OPT => decodeEdnsOptions(cursor, length).map(RecordData.OPT.apply)
      case other          => cursor.take(length).map(RecordData.Unknown(other, _))

  private def decodeTxt(
      cursor: WireCursor,
      length: Int
  ): Either[DecodeError, Vector[Vector[Byte]]] =
    val end = cursor.offset + length
    val chunks = Vector.newBuilder[Vector[Byte]]
    var error: Option[DecodeError] = None
    while cursor.offset < end && error.isEmpty do
      cursor.u8().flatMap(cursor.take) match
        case Right(chunk) if cursor.offset <= end => chunks += chunk
        case Right(_)                             =>
          error = Some(DecodeError.InvalidRData(RecordType.TXT, "chunk exceeds RDLENGTH"))
        case Left(value) => error = Some(value)
    error.toLeft(chunks.result())

  private def decodeEdnsOptions(
      cursor: WireCursor,
      length: Int
  ): Either[DecodeError, Vector[EdnsOption]] =
    val end = cursor.offset + length
    val options = Vector.newBuilder[EdnsOption]
    var error: Option[DecodeError] = None
    while cursor.offset < end && error.isEmpty do
      val decoded =
        for
          code <- cursor.u16()
          optionLength <- cursor.u16()
          _ <- Either.cond(
            cursor.offset + optionLength <= end,
            (),
            DecodeError.InvalidRData(RecordType.OPT, "option exceeds RDLENGTH")
          )
          data <- cursor.take(optionLength)
        yield EdnsOption(code, data)
      decoded match
        case Right(option) => options += option
        case Left(value)   => error = Some(value)
    error.toLeft(options.result())

  private def writeRecord(
      writer: WireWriter,
      names: NameCodec.Encoder,
      record: ResourceRecord
  ): Unit =
    names.write(record.name); writer.u16(record.recordType.code);
    writer.u16(record.recordClass.code); writer.u32(record.ttl)
    val dataWriter = new WireWriter()
    val dataNames = new NameCodec.Encoder(dataWriter)
    writeData(dataWriter, dataNames, record.data)
    val bytes = dataWriter.result()
    writer.u16(bytes.length); writer.bytes(bytes)

  private def writeData(writer: WireWriter, names: NameCodec.Encoder, data: RecordData): Unit =
    data match
      case RecordData.A(address)               => writer.bytes(address.getAddress)
      case RecordData.AAAA(address)            => writer.bytes(address.getAddress)
      case RecordData.NS(name)                 => names.writeUncompressed(name)
      case RecordData.CName(name)              => names.writeUncompressed(name)
      case RecordData.Ptr(name)                => names.writeUncompressed(name)
      case RecordData.MX(preference, exchange) =>
        writer.u16(preference); names.writeUncompressed(exchange)
      case RecordData.TXT(chunks) =>
        chunks.foreach { chunk => writer.u8(chunk.size); writer.bytes(chunk) }
      case RecordData.SOA(primary, mailbox, serial, refresh, retry, expire, minimum) =>
        names.writeUncompressed(primary); names.writeUncompressed(mailbox);
        Vector(serial, refresh, retry, expire, minimum).foreach(writer.u32)
      case RecordData.SRV(priority, weight, port, target) =>
        writer.u16(priority); writer.u16(weight); writer.u16(port); names.writeUncompressed(target)
      case RecordData.OPT(options) =>
        options.foreach { option =>
          writer.u16(option.code)
          writer.u16(option.data.size)
          writer.bytes(option.data)
        }
      case RecordData.Unknown(_, bytes) => writer.bytes(bytes)

  private def decodeFlags(bits: Int): Flags = Flags(
    response = (bits & 0x8000) != 0,
    opCode = OpCode.fromInt((bits >>> 11) & 0xf),
    authoritative = (bits & 0x400) != 0,
    truncated = (bits & 0x200) != 0,
    recursionDesired = (bits & 0x100) != 0,
    recursionAvailable = (bits & 0x80) != 0,
    authenticatedData = (bits & 0x20) != 0,
    checkingDisabled = (bits & 0x10) != 0,
    responseCode = ResponseCode.fromInt(bits & 0xf)
  )
  private def encodeFlags(flags: Flags): Int =
    (if flags.response then 0x8000 else 0) |
      ((flags.opCode.code & 0xf) << 11) |
      (if flags.authoritative then 0x400 else 0) |
      (if flags.truncated then 0x200 else 0) |
      (if flags.recursionDesired then 0x100 else 0) |
      (if flags.recursionAvailable then 0x80 else 0) |
      (if flags.authenticatedData then 0x20 else 0) |
      (if flags.checkingDisabled then 0x10 else 0) |
      (flags.responseCode.code & 0xf)

  private def validateCount(section: String, count: Int, limit: Int): Either[DecodeError, Unit] =
    Either.cond(count <= limit, (), DecodeError.CountLimit(section, count, limit))
  private def repeat[A](
      count: Int
  )(value: => Either[DecodeError, A]): Either[DecodeError, Vector[A]] = (0 until count)
    .foldLeft(Right(Vector.empty): Either[DecodeError, Vector[A]])((result, _) =>
      result.flatMap(values => value.map(values :+ _))
    )
