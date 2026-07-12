package dns.cli

import dns.*
import java.net.InetSocketAddress
import scala.concurrent.duration.*

/** `dns-query` entry point for sending one validated DNS question. */
object DnsQuery:
  final case class Config(
      name: DomainName,
      recordType: RecordType,
      server: InetSocketAddress,
      timeout: FiniteDuration,
      udpPayloadSize: Int,
      enableEdns: Boolean
  )

  def main(args: Array[String]): Unit =
    parse(args.toVector) match
      case Left(error) =>
        System.err.println(error)
        System.err.println(usage)
        sys.exit(2)
      case Right(config) =>
        val client =
          new DnsClient(config.server, config.timeout, config.udpPayloadSize, config.enableEdns)
        client.query(config.name, config.recordType) match
          case Right(response) => println(Presentation.message(response))
          case Left(error)     =>
            System.err.println(s"query failed: $error")
            sys.exit(1)

  private[cli] def parse(args: Vector[String]): Either[String, Config] =
    args match
      case nameText +: remaining =>
        for
          name <- DomainName.fromString(nameText).left.map(error => s"invalid name: $error")
          parsed <- parseOptions(remaining, defaults(name))
        yield parsed
      case _ => Left("missing domain name")

  private def defaults(name: DomainName): Config = Config(
    name,
    RecordType.A,
    new InetSocketAddress("1.1.1.1", 53),
    3.seconds,
    1232,
    enableEdns = true
  )

  private def parseOptions(tokens: Vector[String], config: Config): Either[String, Config] =
    tokens match
      case Vector()                    => Right(config)
      case "--server" +: value +: tail =>
        socket(value).flatMap(server => parseOptions(tail, config.copy(server = server)))
      case "--timeout-ms" +: value +: tail =>
        positiveInt(value, "timeout")
          .flatMap(milliseconds => parseOptions(tail, config.copy(timeout = milliseconds.millis)))
      case "--udp-size" +: value +: tail =>
        positiveInt(value, "UDP size").flatMap { size =>
          Either.cond(size >= 512 && size <= 65535, size, "UDP size must be between 512 and 65535")
        }.flatMap(size => parseOptions(tail, config.copy(udpPayloadSize = size)))
      case "--no-edns" +: tail => parseOptions(tail, config.copy(enableEdns = false))
      case value +: tail if !value.startsWith("--") =>
        recordType(value).flatMap(kind => parseOptions(tail, config.copy(recordType = kind)))
      case option +: _ => Left(s"unknown or incomplete option: $option")
      case _           => Left("invalid query options")

  private def recordType(value: String): Either[String, RecordType] =
    value.toUpperCase match
      case "A"     => Right(RecordType.A)
      case "AAAA"  => Right(RecordType.AAAA)
      case "NS"    => Right(RecordType.NS)
      case "CNAME" => Right(RecordType.CNAME)
      case "PTR"   => Right(RecordType.PTR)
      case "MX"    => Right(RecordType.MX)
      case "TXT"   => Right(RecordType.TXT)
      case "SOA"   => Right(RecordType.SOA)
      case "SRV"   => Right(RecordType.SRV)
      case "ANY"   => Right(RecordType.ANY)
      case other   => Left(s"unsupported query type: $other")

  private def socket(value: String): Either[String, InetSocketAddress] =
    val (host, portText) =
      if value.startsWith("[") && value.contains("]") then
        val closing = value.indexOf(']')
        val host = value.slice(1, closing)
        val port = Option.when(value.length > closing + 1)(value.drop(closing + 2))
        host -> port
      else if value.count(_ == ':') == 1 then
        val separator = value.indexOf(':')
        value.take(separator) -> Some(value.drop(separator + 1))
      else value -> None
    portText.map(_.toIntOption).getOrElse(Some(53)).filter(number => number > 0 && number <= 65535)
      .map(number => new InetSocketAddress(host, number)).toRight(s"invalid server address: $value")

  private def positiveInt(value: String, name: String): Either[String, Int] = value.toIntOption
    .filter(_ > 0).toRight(s"$name must be a positive integer")

  val usage: String =
    "Usage: dns.cli.DnsQuery <name> [TYPE] [--server host[:port]] " +
      "[--timeout-ms n] [--udp-size n] [--no-edns]"
