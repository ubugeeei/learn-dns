package dns

import java.util.concurrent.ConcurrentHashMap

/** Monotonic time source used to make TTL behavior deterministic in tests. */
trait Ticker:
  def nanos: Long

object Ticker:
  val system: Ticker =
    new Ticker:
      def nanos: Long = System.nanoTime()

/**
 * A thread-safe DNS cache that stores complete positive or negative answers.
 *
 * TTL handling follows [[https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1 RFC 1035 §3.2.1]].
 * Negative answers use the SOA rule from
 * [[https://www.rfc-editor.org/rfc/rfc2308#section-5 RFC 2308 §5]]. The cache uses monotonic time,
 * so wall-clock corrections cannot resurrect entries.
 *
 * NXDOMAIN is keyed by name and class because it denies the whole name; NODATA remains keyed by the
 * complete question. A DNSSEC-aware resolver must extend these keys with validation and
 * checking-disabled state.
 */
final class Cache(ticker: Ticker = Ticker.system, maxEntries: Int = 10000):
  require(maxEntries > 0)

  private enum Key:
    case QuestionKey(question: Question)
    case NameErrorKey(name: DomainName, recordClass: RecordClass)

  private final case class Entry(storedAt: Long, expiresAt: Long, message: Message)
  private val entries = new ConcurrentHashMap[Key, Entry]()

  /** Returns a cached response with every TTL reduced by elapsed whole seconds. */
  def get(question: Question): Option[Message] = get(
    Key.NameErrorKey(question.name, question.recordClass)
  ).orElse(get(Key.QuestionKey(question)))

  private def get(key: Key): Option[Message] = Option(entries.get(key)).flatMap { entry =>
    val now = ticker.nanos
    if now >= entry.expiresAt then
      entries.remove(key, entry)
      None
    else
      val elapsedSeconds = math.max(0L, (now - entry.storedAt) / 1_000_000_000L)
      Some(adjustTtls(entry.message, elapsedSeconds))
  }

  /** Stores cacheable NOERROR or NXDOMAIN responses and returns whether stored. */
  def put(question: Question, response: Message): Boolean =
    cacheTtl(response) match
      case Some(ttl) if ttl > 0 =>
        val now = ticker.nanos
        val lifetime = saturatedNanos(ttl)
        val key =
          response.flags.responseCode match
            case ResponseCode.NameError => Key.NameErrorKey(question.name, question.recordClass)
            case _                      => Key.QuestionKey(question)
        if !entries.containsKey(key) && entries.size() >= maxEntries then evictEarliest()
        entries.put(key, Entry(now, saturatedAdd(now, lifetime), normalizeNegative(response, ttl)))
        true
      case _ => false

  def remove(question: Question): Unit =
    entries.remove(Key.QuestionKey(question)): Unit
    entries.remove(Key.NameErrorKey(question.name, question.recordClass)): Unit
  def clear(): Unit = entries.clear()
  def size: Int = entries.size()

  private def cacheTtl(message: Message): Option[Long] =
    message.flags.responseCode match
      case ResponseCode.NoError if message.answers.nonEmpty =>
        Some(message.answers.iterator.map(_.ttl).min)
      case ResponseCode.NoError | ResponseCode.NameError => negativeTtl(message)
      case _                                             => None

  private def negativeTtl(message: Message): Option[Long] = message.authorities.collectFirst {
    case ResourceRecord(_, _, ttl, soa: RecordData.SOA) => math.min(ttl, soa.minimum)
  }

  private def normalizeNegative(message: Message, ttl: Long): Message =
    if message.answers.nonEmpty then message
    else
      message.copy(authorities = message.authorities.map {
        case record if record.recordType == RecordType.SOA =>
          record.copy(ttl = math.min(record.ttl, ttl))
        case record => record
      })

  private def evictEarliest(): Unit =
    val iterator = entries.entrySet().iterator()
    var earliest: Option[java.util.Map.Entry[Key, Entry]] = None
    while iterator.hasNext do
      val candidate = iterator.next()
      if earliest.forall(_.getValue.expiresAt > candidate.getValue.expiresAt) then
        earliest = Some(candidate)
    earliest.foreach(entry => entries.remove(entry.getKey, entry.getValue): Unit)

  private def adjustTtls(message: Message, elapsed: Long): Message =
    def section(records: Vector[ResourceRecord]): Vector[ResourceRecord] = records
      .map(record => record.copy(ttl = math.max(0L, record.ttl - elapsed)))
    message.copy(
      answers = section(message.answers),
      authorities = section(message.authorities),
      additionals = section(message.additionals)
    )

  private def saturatedNanos(seconds: Long): Long =
    if seconds > Long.MaxValue / 1_000_000_000L then Long.MaxValue else seconds * 1_000_000_000L

  private def saturatedAdd(left: Long, right: Long): Long =
    if right > 0 && left > Long.MaxValue - right then Long.MaxValue else left + right
