package dns

import java.net.{ Inet4Address, Inet6Address, InetAddress }

/** Literal-only IP address parsing that never performs a DNS lookup. */
object IpAddress:
  enum Error derives CanEqual:
    case InvalidIpv4(value: String)
    case InvalidIpv6(value: String)

  def ipv4(value: String): Either[Error, Inet4Address] =
    val pieces = value.split("\\.", -1).toVector
    val octets = pieces.map(piece =>
      Option.when(piece.nonEmpty && piece.forall(_.isDigit))(piece.toIntOption).flatten
        .filter(number => number >= 0 && number <= 255)
    )
    if pieces.size != 4 || octets.exists(_.isEmpty) then Left(Error.InvalidIpv4(value))
    else
      val bytes = octets.flatten.map(_.toByte).toArray
      Right(InetAddress.getByAddress(bytes).asInstanceOf[Inet4Address])

  def ipv6(value: String): Either[Error, Inet6Address] =
    if !value.contains(":") || value.contains("%") then Left(Error.InvalidIpv6(value))
    else
      scala.util.Try(InetAddress.getByName(value)).toOption.collect { case address: Inet6Address =>
        address
      }.toRight(Error.InvalidIpv6(value))
