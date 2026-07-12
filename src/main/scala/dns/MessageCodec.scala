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
  def encodeValidated(message: Message): Either[EncodeError, Array[Byte]] = MessageEncoder
    .encode(message)

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
  private def validateCount(section: String, count: Int, limit: Int): Either[DecodeError, Unit] =
    Either.cond(count <= limit, (), DecodeError.CountLimit(section, count, limit))
  private def repeat[A](
      count: Int
  )(value: => Either[DecodeError, A]): Either[DecodeError, Vector[A]] = (0 until count)
    .foldLeft(Right(Vector.empty): Either[DecodeError, Vector[A]])((result, _) =>
      result.flatMap(values => value.map(values :+ _))
    )
