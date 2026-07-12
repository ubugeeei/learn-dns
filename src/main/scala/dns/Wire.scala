package dns

import java.io.ByteArrayOutputStream

/** Bounds-checked primitives shared by DNS wire decoders. */
private[dns] final class WireCursor(val bytes: Array[Byte], private var position: Int = 0):
  import DecodeError.*

  def offset: Int = position
  def remaining: Int = bytes.length - position
  def seek(next: Int): Either[DecodeError, Unit] =
    if next < 0 || next > bytes.length then Left(UnexpectedEnd(next, bytes.length))
    else { position = next; Right(()) }
  def u8(): Either[DecodeError, Int] =
    if remaining < 1 then Left(UnexpectedEnd(position, bytes.length))
    else { val value = bytes(position) & 0xff; position += 1; Right(value) }
  def u16(): Either[DecodeError, Int] =
    for high <- u8(); low <- u8() yield (high << 8) | low
  def u32(): Either[DecodeError, Long] =
    for high <- u16(); low <- u16() yield ((high.toLong << 16) | low.toLong) & 0xffffffffL
  def take(length: Int): Either[DecodeError, Vector[Byte]] =
    if length < 0 || remaining < length then Left(UnexpectedEnd(position + length, bytes.length))
    else
      val result = bytes.slice(position, position + length).toVector
      position += length
      Right(result)

/** Structured failures returned for all untrusted wire input. */
enum DecodeError derives CanEqual:
  case UnexpectedEnd(requiredOffset: Int, packetLength: Int)
  case InvalidLabelTag(offset: Int, value: Int)
  case CompressionLoop(offset: Int)
  case CompressionPointerLimit(limit: Int)
  case CompressionPointerOutOfBounds(pointer: Int, packetLength: Int)
  case InvalidName(error: DomainName.Error)
  case InvalidRData(recordType: RecordType, detail: String)
  case TrailingRData(recordType: RecordType, remaining: Int)
  case CountLimit(section: String, count: Int, limit: Int)
  case TrailingBytes(count: Int)

/** Why a typed message cannot be represented by the bounded DNS wire format. */
enum EncodeError derives CanEqual:
  case SectionCount(section: String, count: Int)
  case TxtChunkTooLong(length: Int)
  case RDataTooLong(recordType: RecordType, length: Long)
  case MessageTooLong(estimatedLength: Long, limit: Int)

/** Validated encoder sink for unsigned network-order integers. */
private[dns] final class WireWriter:
  private val output = ByteArrayOutputStream()
  def size: Int = output.size()
  def u8(value: Int): Unit = output.write(value & 0xff)
  def u16(value: Int): Unit = { u8(value >>> 8); u8(value) }
  def u32(value: Long): Unit = { u16((value >>> 16).toInt); u16(value.toInt) }
  def bytes(values: IterableOnce[Byte]): Unit = values.iterator
    .foreach(value => output.write(value & 0xff))
  def result(): Array[Byte] = output.toByteArray
