package dns.cli

import dns.*
import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.nio.file.{ Files, Path }
import java.util.concurrent.CountDownLatch

/** `dns-serve` entry point for one authoritative master file. */
object DnsServe:
  final case class Config(
      zoneFile: Path,
      origin: DomainName,
      bindAddress: InetAddress,
      port: Int,
      maxUdpResponseBytes: Int
  )

  def main(args: Array[String]): Unit =
    parse(args.toVector).flatMap(load) match
      case Left(error) =>
        System.err.println(error)
        System.err.println(usage)
        sys.exit(2)
      case Right((config, zone)) =>
        val server = DnsServer.start(
          zone.answer,
          DnsServer.Config(
            bindAddress = config.bindAddress,
            port = config.port,
            maxUdpResponseBytes = config.maxUdpResponseBytes
          )
        )
        val stopped = new CountDownLatch(1)
        Runtime.getRuntime.addShutdownHook(new Thread(() =>
          server.close()
          stopped.countDown()
        ))
        println(
          s"serving ${config.origin} on ${server.address.getHostString}:${server.address.getPort}"
        )
        stopped.await()

  private[cli] def parse(args: Vector[String]): Either[String, Config] =
    args match
      case file +: originText +: options =>
        DomainName.fromString(originText).left.map(error => s"invalid origin: $error")
          .flatMap { origin =>
            parseOptions(
              options,
              Config(Path.of(file), origin, InetAddress.getLoopbackAddress, 5353, 1232)
            )
          }
      case _ => Left("zone file and origin are required")

  private[cli] def load(config: Config): Either[String, (Config, Zone)] = scala.util
    .Try(Files.readString(config.zoneFile, StandardCharsets.UTF_8)).toEither.left
    .map(error => s"cannot read ${config.zoneFile}: ${error.getMessage}").flatMap { input =>
      ZoneFile.parse(input, config.origin).left.map { diagnostics =>
        diagnostics.map(value => s"${config.zoneFile}:${value.line}: ${value.message}")
          .mkString("\n")
      }.map(zone => config -> zone)
    }

  private def parseOptions(tokens: Vector[String], config: Config): Either[String, Config] =
    tokens match
      case Vector()                  => Right(config)
      case "--bind" +: value +: tail =>
        scala.util.Try(InetAddress.getByName(value)).toEither.left
          .map(_ => s"invalid bind address: $value")
          .flatMap(address => parseOptions(tail, config.copy(bindAddress = address)))
      case "--port" +: value +: tail =>
        port(value).flatMap(number => parseOptions(tail, config.copy(port = number)))
      case "--udp-size" +: value +: tail =>
        value.toIntOption.filter(number => number >= 512 && number <= 65535)
          .toRight("UDP size must be between 512 and 65535")
          .flatMap(number => parseOptions(tail, config.copy(maxUdpResponseBytes = number)))
      case option +: _ => Left(s"unknown or incomplete option: $option")
      case _           => Left("invalid server options")

  private def port(value: String): Either[String, Int] = value.toIntOption
    .filter(number => number >= 0 && number <= 65535).toRight("port must be between 0 and 65535")

  val usage: String =
    "Usage: dns.cli.DnsServe <zone-file> <origin> [--bind address] " + "[--port n] [--udp-size n]"
