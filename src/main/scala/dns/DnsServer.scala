package dns

import java.io.{ DataInputStream, DataOutputStream, EOFException }
import java.net.{
  DatagramPacket, DatagramSocket, InetAddress, InetSocketAddress, ServerSocket, Socket,
  SocketException
}
import java.util.concurrent.{ ExecutorService, Executors, Semaphore, TimeUnit }
import java.util.concurrent.atomic.{ AtomicBoolean, LongAdder }

/**
 * A dual-protocol authoritative DNS server with a bounded work queue.
 *
 * UDP and TCP are required transports for general-purpose DNS implementations; see
 * [[https://www.rfc-editor.org/rfc/rfc7766 RFC 7766]]. The server binds both transports to one
 * port, truncates oversized UDP responses, frames TCP messages, bounds concurrent handlers, and
 * supports deterministic shutdown.
 *
 * `handler` is deliberately a pure message boundary. Zone lookup, forwarding, or recursion can be
 * colocated with their policy and tested without sockets.
 */
final class DnsServer private (
    val address: InetSocketAddress,
    udpSocket: DatagramSocket,
    tcpSocket: ServerSocket,
    handler: Message => Message,
    config: DnsServer.Config,
    workers: ExecutorService
) extends AutoCloseable:
  import DnsServer.*

  private val running = new AtomicBoolean(true)
  private val permits = new Semaphore(config.maxConcurrentRequests)
  private val received = new LongAdder()
  private val answered = new LongAdder()
  private val rejected = new LongAdder()
  private val malformed = new LongAdder()

  private val udpThread = Thread.ofVirtual().name("dns-udp-listener").start(() => udpLoop())
  private val tcpThread = Thread.ofVirtual().name("dns-tcp-listener").start(() => tcpLoop())

  def metrics: Metrics = Metrics(received.sum(), answered.sum(), rejected.sum(), malformed.sum())

  override def close(): Unit =
    if running.compareAndSet(true, false) then
      udpSocket.close()
      tcpSocket.close()
      workers.shutdown()
      workers.awaitTermination(config.shutdownTimeoutMillis, TimeUnit.MILLISECONDS): Unit
      workers.shutdownNow(): Unit
      udpThread.join(config.shutdownTimeoutMillis)
      tcpThread.join(config.shutdownTimeoutMillis)

  private def udpLoop(): Unit =
    while running.get() do
      val bytes = Array.ofDim[Byte](config.maxUdpRequestBytes)
      val packet = new DatagramPacket(bytes, bytes.length)
      try
        udpSocket.receive(packet)
        received.increment()
        if permits.tryAcquire() then
          val payload = bytes.slice(0, packet.getLength)
          val peer = packet.getSocketAddress
          workers.execute(() =>
            try
              val processed = process(payload)
              val encoded = truncateForUdp(processed.message, processed.udpLimit)
              udpSocket.send(new DatagramPacket(encoded, encoded.length, peer))
              answered.increment()
            finally permits.release()
          )
        else rejected.increment()
      catch
        case _: SocketException if !running.get() => ()
        case _: java.io.IOException               => malformed.increment()

  private def tcpLoop(): Unit =
    while running.get() do
      try
        val socket = tcpSocket.accept()
        received.increment()
        if permits.tryAcquire() then
          workers.execute(() =>
            try handleTcp(socket)
            finally
              socket.close()
              permits.release()
          )
        else
          rejected.increment()
          socket.close()
      catch
        case _: SocketException if !running.get() => ()
        case _: java.io.IOException               => malformed.increment()

  private def handleTcp(socket: Socket): Unit =
    socket.setSoTimeout(config.readTimeoutMillis)
    val input = new DataInputStream(socket.getInputStream)
    val output = new DataOutputStream(socket.getOutputStream)
    var continue = true
    while continue && running.get() do
      try
        val length = input.readUnsignedShort()
        val payload = input.readNBytes(length)
        if payload.length != length then continue = false
        else
          val encoded = MessageCodec.encode(process(payload).message)
          output.writeShort(encoded.length)
          output.write(encoded)
          output.flush()
          answered.increment()
      catch
        case _: EOFException                    => continue = false
        case _: java.net.SocketTimeoutException => continue = false
        case _: java.io.IOException             => continue = false

  private def process(payload: Array[Byte]): Processed =
    MessageCodec.decode(payload) match
      case Right(request) => negotiateEdns(request)
      case Left(_)        =>
        malformed.increment()
        val id = if payload.length >= 2 then ((payload(0) & 0xff) << 8) | (payload(1) & 0xff) else 0
        Processed(
          Message(
            id,
            Flags(
              response = true,
              recursionDesired = false,
              responseCode = ResponseCode.FormatError
            )
          ),
          udpLimit = math.min(512, config.maxUdpResponseBytes)
        )

  private def negotiateEdns(request: Message): Processed =
    val optRecords = request.additionals.filter(_.recordType == RecordType.OPT)
    if optRecords.size > 1 then
      Processed(errorFor(request, ResponseCode.FormatError), legacyUdpLimit)
    else
      optRecords.headOption match
        case None         => Processed(invokeHandler(request), legacyUdpLimit)
        case Some(record) =>
          Edns.fromRecord(record) match
            case None => Processed(errorFor(request, ResponseCode.FormatError), legacyUdpLimit)
            case Some(edns) if edns.version != 0 =>
              val badVersion = errorFor(request, ResponseCode.NoError).copy(additionals =
                Vector(
                  Edns(udpPayloadSize = config.maxUdpResponseBytes, extendedResponseCode = 1)
                    .toRecord
                )
              )
              Processed(badVersion, math.min(edns.udpPayloadSize, config.maxUdpResponseBytes))
            case Some(edns) =>
              val base = invokeHandler(request)
              val response = base.copy(additionals =
                base.additionals.filterNot(_.recordType == RecordType.OPT) :+
                  Edns(config.maxUdpResponseBytes).toRecord
              )
              Processed(response, math.min(edns.udpPayloadSize, config.maxUdpResponseBytes))

  private def invokeHandler(request: Message): Message =
    try handler(request)
    catch case scala.util.control.NonFatal(_) => errorFor(request, ResponseCode.ServerFailure)

  private def legacyUdpLimit: Int = math.min(512, config.maxUdpResponseBytes)

  private def errorFor(request: Message, code: ResponseCode): Message = Message(
    request.id,
    Flags(
      response = true,
      opCode = request.flags.opCode,
      recursionDesired = request.flags.recursionDesired,
      responseCode = code
    ),
    request.questions
  )

  private def truncateForUdp(message: Message, limit: Int): Array[Byte] =
    var candidate = message
    var encoded = MessageCodec.encode(candidate)
    while encoded.length > limit &&
      (candidate.additionals.nonEmpty || candidate.authorities.nonEmpty ||
        candidate.answers.nonEmpty)
    do
      candidate =
        if candidate.additionals.nonEmpty then
          candidate.copy(additionals = candidate.additionals.dropRight(1))
        else if candidate.authorities.nonEmpty then
          candidate.copy(authorities = candidate.authorities.dropRight(1))
        else candidate.copy(answers = candidate.answers.dropRight(1))
      encoded = MessageCodec.encode(candidate.copy(flags = candidate.flags.copy(truncated = true)))
    if encoded.length > limit then
      MessageCodec.encode(
        candidate.copy(flags = candidate.flags.copy(truncated = true), questions = Vector.empty)
      )
    else encoded

object DnsServer:
  private final case class Processed(message: Message, udpLimit: Int)

  final case class Config(
      bindAddress: InetAddress = InetAddress.getLoopbackAddress,
      port: Int = 0,
      maxConcurrentRequests: Int = 256,
      maxUdpRequestBytes: Int = 4096,
      maxUdpResponseBytes: Int = 1232,
      readTimeoutMillis: Int = 5000,
      shutdownTimeoutMillis: Long = 5000
  ):
    require(port >= 0 && port <= 65535)
    require(maxConcurrentRequests > 0)
    require(maxUdpRequestBytes >= 512 && maxUdpRequestBytes <= 65535)
    require(maxUdpResponseBytes >= 512 && maxUdpResponseBytes <= 65535)

  final case class Metrics(received: Long, answered: Long, rejected: Long, malformed: Long)

  def start(handler: Message => Message, config: Config = Config()): DnsServer =
    val tcp = new ServerSocket()
    tcp.setReuseAddress(true)
    tcp.bind(new InetSocketAddress(config.bindAddress, config.port))
    val address = new InetSocketAddress(config.bindAddress, tcp.getLocalPort)
    val udp = new DatagramSocket(null)
    try
      udp.setReuseAddress(true)
      udp.bind(address)
      val workers = Executors.newVirtualThreadPerTaskExecutor()
      new DnsServer(address, udp, tcp, handler, config, workers)
    catch
      case error: Throwable =>
        udp.close()
        tcp.close()
        throw error
