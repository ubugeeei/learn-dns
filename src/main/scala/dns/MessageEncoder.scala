package dns

/** Validating DNS message encoder, colocated with all outbound wire limits. */
private[dns] object MessageEncoder:
  def encode(message: Message): Either[EncodeError, Array[Byte]] =
    validate(message).map(_ => encodeUnchecked(message))

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
      names.write(question.name)
      writer.u16(question.recordType.code)
      writer.u16(question.recordClass.code)
    }
    (message.answers ++ message.authorities ++ message.additionals)
      .foreach(writeRecord(writer, names, _))
    writer.result()

  private def validate(message: Message): Either[EncodeError, Unit] =
    val sections = Vector(
      "question" -> message.questions.size,
      "answer" -> message.answers.size,
      "authority" -> message.authorities.size,
      "additional" -> message.additionals.size
    )
    sections.find(_._2 > 0xffff) match
      case Some((name, count)) => Left(EncodeError.SectionCount(name, count))
      case None =>
        val records = message.answers ++ message.authorities ++ message.additionals
        records.iterator.map(validateRecord).collectFirst { case Left(error) => Left(error) }
          .getOrElse(validateEstimatedLength(message, records))

  private def validateEstimatedLength(
      message: Message,
      records: Vector[ResourceRecord]
  ): Either[EncodeError, Unit] =
    val questionBytes = message.questions.iterator
      .map(question => question.name.wireLength.toLong + 4).sum
    val recordBytes = records.iterator
      .map(record => record.name.wireLength.toLong + 10 + rdataLength(record.data)).sum
    val estimated = 12L + questionBytes + recordBytes
    Either.cond(
      estimated <= MessageCodec.MaxWireMessageBytes,
      (),
      EncodeError.MessageTooLong(estimated, MessageCodec.MaxWireMessageBytes)
    )

  private def validateRecord(record: ResourceRecord): Either[EncodeError, Unit] =
    record.data match
      case RecordData.MX(preference, _) => unsigned(record, "preference", preference, 16)
      case RecordData.SRV(priority, weight, port, _) =>
        unsigned(record, "priority", priority, 16)
          .flatMap(_ => unsigned(record, "weight", weight, 16))
          .flatMap(_ => unsigned(record, "port", port, 16))
      case RecordData.SOA(_, _, serial, refresh, retry, expire, minimum) =>
        Vector(
          "serial" -> serial,
          "refresh" -> refresh,
          "retry" -> retry,
          "expire" -> expire,
          "minimum" -> minimum
        ).iterator.map((field, value) => unsigned(record, field, value, 32)).collectFirst {
          case Left(error) => Left(error)
        }.getOrElse(Right(()))
      case RecordData.TXT(chunks) =>
        chunks.find(_.size > 255) match
          case Some(chunk) => Left(EncodeError.TxtChunkTooLong(chunk.size))
          case None        => validateRdataLength(record)
      case _ => validateRdataLength(record)

  private def validateRdataLength(record: ResourceRecord): Either[EncodeError, Unit] =
    val length = rdataLength(record.data)
    Either.cond(length <= 0xffff, (), EncodeError.RDataTooLong(record.recordType, length))

  private def unsigned(
      record: ResourceRecord,
      field: String,
      value: Long,
      bits: Int
  ): Either[EncodeError, Unit] =
    val maximum = if bits == 16 then 0xffffL else 0xffffffffL
    Either.cond(
      value >= 0 && value <= maximum,
      (),
      EncodeError.FieldOutOfRange(record.recordType, field, value, bits)
    )

  private def rdataLength(data: RecordData): Long = data match
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
    case RecordData.OPT(options) => options.iterator.map(_.data.size.toLong + 4).sum
    case RecordData.Unknown(_, bytes) => bytes.size.toLong

  private def writeRecord(
      writer: WireWriter,
      names: NameCodec.Encoder,
      record: ResourceRecord
  ): Unit =
    names.write(record.name)
    writer.u16(record.recordType.code)
    writer.u16(record.recordClass.code)
    writer.u32(record.ttl)
    val dataWriter = new WireWriter()
    writeData(dataWriter, new NameCodec.Encoder(dataWriter), record.data)
    val bytes = dataWriter.result()
    writer.u16(bytes.length)
    writer.bytes(bytes)

  private def writeData(writer: WireWriter, names: NameCodec.Encoder, data: RecordData): Unit =
    data match
      case RecordData.A(address)    => writer.bytes(address.getAddress)
      case RecordData.AAAA(address) => writer.bytes(address.getAddress)
      case RecordData.NS(name)      => names.writeUncompressed(name)
      case RecordData.CName(name)   => names.writeUncompressed(name)
      case RecordData.Ptr(name)     => names.writeUncompressed(name)
      case RecordData.MX(preference, exchange) =>
        writer.u16(preference)
        names.writeUncompressed(exchange)
      case RecordData.TXT(chunks) =>
        chunks.foreach { chunk => writer.u8(chunk.size); writer.bytes(chunk) }
      case RecordData.SOA(primary, mailbox, serial, refresh, retry, expire, minimum) =>
        names.writeUncompressed(primary)
        names.writeUncompressed(mailbox)
        Vector(serial, refresh, retry, expire, minimum).foreach(writer.u32)
      case RecordData.SRV(priority, weight, port, target) =>
        writer.u16(priority)
        writer.u16(weight)
        writer.u16(port)
        names.writeUncompressed(target)
      case RecordData.OPT(options) =>
        options.foreach { option =>
          writer.u16(option.code)
          writer.u16(option.data.size)
          writer.bytes(option.data)
        }
      case RecordData.Unknown(_, bytes) => writer.bytes(bytes)

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
