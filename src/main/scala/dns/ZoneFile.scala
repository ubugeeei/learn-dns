package dns

import java.nio.charset.StandardCharsets

/**
 * Parser for the common RFC 1035 master-file subset used by authoritative zones.
 *
 * Supported directives are `$ORIGIN` and `$TTL`; supported records are A, AAAA, NS, CNAME, PTR, MX,
 * TXT, SOA, and SRV. The parser understands relative names, `@`, omitted owners, comments, quoted
 * escapes, and parenthesized SOA. All diagnostics include the originating logical line and are
 * accumulated.
 */
object ZoneFile:
  final case class Config(
      maxInputBytes: Int = 4 * 1024 * 1024,
      maxLogicalLineLength: Int = 64 * 1024,
      maxRecords: Int = 100000
  ):
    require(maxInputBytes > 0)
    require(maxLogicalLineLength > 0)
    require(maxRecords > 0)

  final case class Diagnostic(line: Int, message: String) derives CanEqual

  def parse(
      input: String,
      initialOrigin: DomainName,
      config: Config = Config()
  ): Either[Vector[Diagnostic], Zone] =
    if input.getBytes(StandardCharsets.UTF_8).length > config.maxInputBytes then
      Left(Vector(Diagnostic(1, s"zone file exceeds ${config.maxInputBytes} bytes")))
    else
      ZoneFileSyntax.statements(input, config.maxLogicalLineLength)
        .flatMap(statements => parseStatements(statements, initialOrigin, config))

  private final case class State(
      origin: DomainName,
      defaultTtl: Option[Long],
      previousOwner: Option[DomainName],
      records: Vector[ResourceRecord],
      diagnostics: Vector[Diagnostic]
  )

  private def parseStatements(
      statements: Vector[ZoneFileSyntax.Statement],
      initialOrigin: DomainName,
      config: Config
  ): Either[Vector[Diagnostic], Zone] =
    val finalState =
      statements.foldLeft(State(initialOrigin, None, None, Vector.empty, Vector.empty)) {
        (state, statement) =>
          if state.records.size >= config.maxRecords then
            state.copy(diagnostics =
              state.diagnostics :+
                Diagnostic(statement.line, s"record count exceeds ${config.maxRecords}")
            )
          else if statement.tokens.head.startsWith("$") then parseDirective(state, statement)
          else parseRecord(state, statement)
      }
    if finalState.diagnostics.nonEmpty then Left(finalState.diagnostics)
    else buildZone(initialOrigin, finalState.records)

  private def parseDirective(state: State, statement: ZoneFileSyntax.Statement): State =
    statement.tokens.map(_.toUpperCase) match
      case Vector("$ORIGIN", _) =>
        absoluteName(statement.tokens(1), state.origin, statement.line) match
          case Right(origin) => state.copy(origin = origin)
          case Left(error)   => state.copy(diagnostics = state.diagnostics :+ error)
      case Vector("$TTL", _) =>
        ttl(statement.tokens(1), statement.line) match
          case Right(value) => state.copy(defaultTtl = Some(value))
          case Left(error)  => state.copy(diagnostics = state.diagnostics :+ error)
      case _ =>
        state.copy(diagnostics =
          state.diagnostics :+ Diagnostic(
            statement.line,
            s"unsupported or malformed directive: ${statement.tokens.head}"
          )
        )

  private def parseRecord(state: State, statement: ZoneFileSyntax.Statement): State =
    val tokens = statement.tokens
    val ownerResult =
      if statement.ownerOmitted then
        state.previousOwner.toRight(Diagnostic(statement.line, "owner omitted before first record"))
      else absoluteName(tokens.head, state.origin, statement.line)
    ownerResult match
      case Left(error)  => state.copy(diagnostics = state.diagnostics :+ error)
      case Right(owner) =>
        val remainder = if statement.ownerOmitted then tokens else tokens.tail
        parseRecordTail(owner, remainder, state, statement.line) match
          case Right(record) =>
            state.copy(previousOwner = Some(owner), records = state.records :+ record)
          case Left(error) =>
            state.copy(previousOwner = Some(owner), diagnostics = state.diagnostics :+ error)

  private def parseRecordTail(
      owner: DomainName,
      tokens: Vector[String],
      state: State,
      line: Int
  ): Either[Diagnostic, ResourceRecord] =
    var remaining = tokens
    var recordTtl = state.defaultTtl
    if remaining.headOption.exists(isTtl) then
      recordTtl = ttl(remaining.head, line).toOption
      remaining = remaining.tail
    if remaining.headOption.exists(_.equalsIgnoreCase("IN")) then remaining = remaining.tail
    for
      seconds <- recordTtl.toRight(Diagnostic(line, "record has no TTL and no $TTL default"))
      kind <- remaining.headOption.toRight(Diagnostic(line, "missing record type"))
      data <- parseData(kind.toUpperCase, remaining.drop(1), state.origin, line)
    yield ResourceRecord(owner, RecordClass.IN, seconds, data)

  private def parseData(
      kind: String,
      values: Vector[String],
      origin: DomainName,
      line: Int
  ): Either[Diagnostic, RecordData] =
    def exact(count: Int): Either[Diagnostic, Unit] = Either
      .cond(values.size == count, (), Diagnostic(line, s"$kind expects $count values"))
    def nameAt(index: Int): Either[Diagnostic, DomainName] = values.lift(index)
      .toRight(Diagnostic(line, s"$kind is missing a name")).flatMap(absoluteName(_, origin, line))
    def uint(index: Int, maximum: Int): Either[Diagnostic, Int] = values.lift(index)
      .flatMap(_.toIntOption).filter(value => value >= 0 && value <= maximum)
      .toRight(Diagnostic(line, s"invalid $kind integer at position ${index + 1}"))
    kind match
      case "A"     => exact(1).flatMap(_ => address4(values.head, line))
      case "AAAA"  => exact(1).flatMap(_ => address6(values.head, line))
      case "NS"    => exact(1).flatMap(_ => nameAt(0).map(RecordData.NS.apply))
      case "CNAME" => exact(1).flatMap(_ => nameAt(0).map(RecordData.CName.apply))
      case "PTR"   => exact(1).flatMap(_ => nameAt(0).map(RecordData.Ptr.apply))
      case "MX"    =>
        for _ <- exact(2); preference <- uint(0, 0xffff); exchange <- nameAt(1)
        yield RecordData.MX(preference, exchange)
      case "TXT" =>
        Either.cond(
          values.nonEmpty,
          RecordData.TXT(values.map(_.getBytes(StandardCharsets.UTF_8).toVector)),
          Diagnostic(line, "TXT requires at least one string")
        )
      case "SRV" =>
        for
          _ <- exact(4); priority <- uint(0, 0xffff); weight <- uint(1, 0xffff)
          port <- uint(2, 0xffff); target <- nameAt(3)
        yield RecordData.SRV(priority, weight, port, target)
      case "SOA" => parseSoa(values, origin, line)
      case other => Left(Diagnostic(line, s"unsupported record type: $other"))

  private def parseSoa(
      values: Vector[String],
      origin: DomainName,
      line: Int
  ): Either[Diagnostic, RecordData] =
    def number(index: Int): Either[Diagnostic, Long] = values.lift(index)
      .toRight(Diagnostic(line, "SOA is missing a timer")).flatMap(value => ttl(value, line))
    for
      _ <- Either.cond(values.size == 7, (), Diagnostic(line, "SOA expects 7 values"))
      primary <- absoluteName(values(0), origin, line)
      mailbox <- absoluteName(values(1), origin, line)
      serial <- values(2).toLongOption.filter(value => value >= 0 && value <= 0xffffffffL)
        .toRight(Diagnostic(line, "invalid SOA serial"))
      refresh <- number(3); retry <- number(4); expire <- number(5); minimum <- number(6)
    yield RecordData.SOA(primary, mailbox, serial, refresh, retry, expire, minimum)

  private def buildZone(
      origin: DomainName,
      records: Vector[ResourceRecord]
  ): Either[Vector[Diagnostic], Zone] =
    records.find(record => record.name == origin && record.recordType == RecordType.SOA) match
      case None      => Left(Vector(Diagnostic(1, s"zone has no SOA at $origin")))
      case Some(soa) =>
        Zone.create(origin, soa, records.filterNot(_ eq soa)).left
          .map(error => Vector(Diagnostic(1, s"zone validation failed: $error")))

  private def absoluteName(
      value: String,
      origin: DomainName,
      line: Int
  ): Either[Diagnostic, DomainName] =
    val expanded =
      if value == "@" then origin.toString
      else if value.endsWith(".") then value
      else if origin.isRoot then s"$value."
      else s"$value.${origin.toString}"
    DomainName.fromString(expanded).left
      .map(error => Diagnostic(line, s"invalid name '$value': $error"))

  private def isTtl(value: String): Boolean = value.headOption.exists(_.isDigit)

  private def ttl(value: String, line: Int): Either[Diagnostic, Long] =
    val pattern = "(?i)([0-9]+)([wdhms]?)".r
    val factors = Map("" -> 1L, "s" -> 1L, "m" -> 60L, "h" -> 3600L, "d" -> 86400L, "w" -> 604800L)
    val matches = pattern.findAllMatchIn(value).toVector
    val complete = matches.map(_.matched).mkString == value
    val total =
      matches.foldLeft(Option(0L)) { (sum, part) =>
        for
          current <- sum; amount <- part.group(1).toLongOption
          next <-
            scala.util.Try(
              Math.addExact(current, Math.multiplyExact(amount, factors(part.group(2).toLowerCase)))
            ).toOption
        yield next
      }
    total.filter(_ <= 0xffffffffL).filter(_ => complete)
      .toRight(Diagnostic(line, s"invalid TTL: $value"))

  private def address4(value: String, line: Int): Either[Diagnostic, RecordData] = scala.util
    .Try(RecordData.ipv4(value)).toEither.left
    .map(_ => Diagnostic(line, s"invalid IPv4 address: $value"))

  private def address6(value: String, line: Int): Either[Diagnostic, RecordData] = scala.util
    .Try(RecordData.ipv6(value)).toEither.left
    .map(_ => Diagnostic(line, s"invalid IPv6 address: $value"))
