package dns.cli

import dns.*

/** Stable human-readable rendering shared by command-line tools and examples. */
private[cli] object Presentation:
  def message(value: Message): String =
    val status = value.flags.responseCode.toString.toUpperCase
    val flags = Vector(
      Option.when(value.flags.response)("qr"),
      Option.when(value.flags.authoritative)("aa"),
      Option.when(value.flags.truncated)("tc"),
      Option.when(value.flags.recursionDesired)("rd"),
      Option.when(value.flags.recursionAvailable)("ra"),
      Option.when(value.flags.authenticatedData)("ad"),
      Option.when(value.flags.checkingDisabled)("cd")
    ).flatten.mkString(" ")
    val header =
      s";; id: ${value.id}, status: $status, flags: $flags\n" +
        s";; QUERY: ${value.questions.size}, ANSWER: ${value.answers.size}, " +
        s"AUTHORITY: ${value.authorities.size}, ADDITIONAL: ${value.additionals.size}"
    Vector(
      header,
      section("QUESTION", value.questions.map(question)),
      section("ANSWER", value.answers.map(record)),
      section("AUTHORITY", value.authorities.map(record)),
      section("ADDITIONAL", value.additionals.map(record))
    ).filter(_.nonEmpty).mkString("\n\n")

  private def section(name: String, lines: Vector[String]): String =
    if lines.isEmpty then "" else s";; $name SECTION:\n${lines.mkString("\n")}"

  private def question(value: Question): String =
    s"${value.name}\t${value.recordClass}\t${value.recordType}"

  private def record(value: ResourceRecord): String =
    s"${value.name}\t${value.ttl}\t${value.recordClass}\t${value.recordType}\t${data(value.data)}"

  private def data(value: RecordData): String =
    value match
      case RecordData.A(address)               => address.getHostAddress
      case RecordData.AAAA(address)            => address.getHostAddress
      case RecordData.NS(name)                 => name.toString
      case RecordData.CName(name)              => name.toString
      case RecordData.Ptr(name)                => name.toString
      case RecordData.MX(preference, exchange) => s"$preference $exchange"
      case RecordData.TXT(chunks)              => chunks.map(chunk => quoted(chunk)).mkString(" ")
      case RecordData.SOA(primary, mailbox, serial, refresh, retry, expire, minimum) =>
        s"$primary $mailbox $serial $refresh $retry $expire $minimum"
      case RecordData.SRV(priority, weight, port, target) => s"$priority $weight $port $target"
      case RecordData.OPT(options)      => s"; EDNS options: ${options.map(_.code).mkString(",")}"
      case RecordData.Unknown(_, bytes) => bytes.map(byte => f"${byte & 0xff}%02x").mkString

  private def quoted(bytes: Vector[Byte]): String =
    val escaped =
      bytes.iterator.map { byte =>
        val value = byte & 0xff
        if value == '"' || value == '\\' then s"\\${value.toChar}"
        else if value >= 32 && value <= 126 then value.toChar.toString
        else f"\\$value%03d"
      }.mkString
    s"\"$escaped\""
