package dns

import java.io.{DataInputStream, DataOutputStream}
import java.net.{DatagramPacket, DatagramSocket, InetSocketAddress, Socket, SocketTimeoutException}
import java.security.SecureRandom
import scala.concurrent.duration.*

/** Blocking DNS stub client with UDP-to-TCP fallback.
  *
  * TCP retry on the TC bit implements
  * [[https://www.rfc-editor.org/rfc/rfc7766#section-6.1.3 RFC 7766 §6.1.3]].
  * Response IDs and echoed questions are checked to avoid accepting unrelated
  * datagrams. This is a stub, not an iterative recursive resolver.
  */
final class DnsClient(
    server: InetSocketAddress,
    timeout: FiniteDuration = 3.seconds,
    udpPayloadSize: Int = 4096,
    random: SecureRandom = new SecureRandom()
):
  require(udpPayloadSize >= 512 && udpPayloadSize <= 65535)

  enum Error:
    case Timeout
    case Io(cause: java.io.IOException)
    case Decode(error: DecodeError)
    case MismatchedResponse

  def query(name: DomainName, recordType: RecordType): Either[Error, Message] =
    val request = Message(random.nextInt(0x10000), questions = Vector(Question(name, recordType)))
    exchangeUdp(request).flatMap { response =>
      if response.flags.truncated then exchangeTcp(request) else Right(response)
    }

  private def exchangeUdp(request: Message): Either[Error, Message] =
    val socket = new DatagramSocket()
    try
      socket.setSoTimeout(timeout.toMillis.toInt)
      val bytes = MessageCodec.encode(request)
      socket.send(new DatagramPacket(bytes, bytes.length, server))
      val buffer = Array.ofDim[Byte](udpPayloadSize)
      val packet = new DatagramPacket(buffer, buffer.length)
      socket.receive(packet)
      validate(request, buffer.slice(0, packet.getLength))
    catch
      case _: SocketTimeoutException => Left(Error.Timeout)
      case cause: java.io.IOException => Left(Error.Io(cause))
    finally socket.close()

  private def exchangeTcp(request: Message): Either[Error, Message] =
    val socket = new Socket()
    try
      socket.connect(server, timeout.toMillis.toInt)
      socket.setSoTimeout(timeout.toMillis.toInt)
      val bytes = MessageCodec.encode(request)
      val output = new DataOutputStream(socket.getOutputStream)
      output.writeShort(bytes.length); output.write(bytes); output.flush()
      val input = new DataInputStream(socket.getInputStream)
      val length = input.readUnsignedShort()
      validate(request, input.readNBytes(length))
    catch
      case _: SocketTimeoutException => Left(Error.Timeout)
      case cause: java.io.IOException => Left(Error.Io(cause))
    finally socket.close()

  private def validate(request: Message, bytes: Array[Byte]): Either[Error, Message] =
    MessageCodec.decode(bytes).left.map(Error.Decode.apply).flatMap { response =>
      Either.cond(
        response.flags.response && response.id == request.id && response.questions == request.questions,
        response,
        Error.MismatchedResponse
      )
    }

