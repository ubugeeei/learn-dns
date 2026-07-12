package dns.cli

import dns.*
import java.net.{ InetAddress, InetSocketAddress }
import java.util.concurrent.CountDownLatch

/** `dns-recurse` entry point for a caching iterative resolver service. */
object DnsRecurse:
  final case class Config(
      roots: Vector[InetSocketAddress],
      bindAddress: InetAddress,
      port: Int,
      maxUdpResponseBytes: Int
  )

  def main(args: Array[String]): Unit =
    parse(args.toVector) match
      case Left(error) =>
        System.err.println(error)
        System.err.println(usage)
        sys.exit(2)
      case Right(config) =>
        val resolver = new IterativeResolver(config.roots, NameServerClient.network)
        val service = new RecursiveService(resolver, new Cache())
        val server = DnsServer.start(
          service.answer,
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
          s"recursive DNS listening on ${server.address.getHostString}:${server.address.getPort} " +
            s"with ${config.roots.size} root server(s)"
        )
        stopped.await()

  private[cli] def parse(args: Vector[String]): Either[String, Config] =
    parseOptions(
      args,
      Config(Vector.empty, InetAddress.getLoopbackAddress, 5353, 1232)
    ).flatMap(config =>
      Either.cond(config.roots.nonEmpty, config, "at least one --root address is required")
    )

  private def parseOptions(tokens: Vector[String], config: Config): Either[String, Config] =
    tokens match
      case Vector() => Right(config)
      case "--root" +: value +: tail =>
        socket(value).flatMap(root => parseOptions(tail, config.copy(roots = config.roots :+ root)))
      case "--bind" +: value +: tail =>
        scala.util.Try(InetAddress.getByName(value)).toEither
          .left.map(_ => s"invalid bind address: $value")
          .flatMap(address => parseOptions(tail, config.copy(bindAddress = address)))
      case "--port" +: value +: tail =>
        number(value, 0, 65535, "port")
          .flatMap(port => parseOptions(tail, config.copy(port = port)))
      case "--udp-size" +: value +: tail =>
        number(value, 512, 65535, "UDP size")
          .flatMap(size => parseOptions(tail, config.copy(maxUdpResponseBytes = size)))
      case option +: _ => Left(s"unknown or incomplete option: $option")
      case _           => Left("invalid recursive server options")

  private def socket(value: String): Either[String, InetSocketAddress] =
    val (host, portText) =
      if value.startsWith("[") && value.contains("]") then
        val closing = value.indexOf(']')
        value.slice(1, closing) -> Option.when(value.length > closing + 1)(value.drop(closing + 2))
      else if value.count(_ == ':') == 1 then
        val separator = value.indexOf(':')
        value.take(separator) -> Some(value.drop(separator + 1))
      else value -> None
    portText.map(_.toIntOption).getOrElse(Some(53)).filter(port => port > 0 && port <= 65535)
      .flatMap(port => scala.util.Try(new InetSocketAddress(InetAddress.getByName(host), port)).toOption)
      .toRight(s"invalid root address: $value")

  private def number(
      value: String,
      minimum: Int,
      maximum: Int,
      label: String
  ): Either[String, Int] = value.toIntOption.filter(number => number >= minimum && number <= maximum)
    .toRight(s"$label must be between $minimum and $maximum")

  val usage: String =
    "Usage: dns.cli.DnsRecurse --root address[:port] [--root ...] " +
      "[--bind address] [--port n] [--udp-size n]"

