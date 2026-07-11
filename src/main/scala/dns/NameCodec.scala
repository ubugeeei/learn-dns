package dns

import scala.collection.mutable

/** RFC 1035 domain-name wire codec with suffix compression.
  *
  * Decoding follows pointers without moving the caller past the pointer target,
  * rejects cycles, and limits traversal to the packet. These requirements close
  * the classic parser hazards described by
  * [[https://www.rfc-editor.org/rfc/rfc9267 RFC 9267]].
  */
private[dns] object NameCodec:
  def decode(cursor: WireCursor): Either[DecodeError, DomainName] =
    val labels = Vector.newBuilder[Vector[Byte]]
    val visited = mutable.Set.empty[Int]
    var scan = cursor.offset
    var resume: Option[Int] = None
    var done = false
    var failure: Option[DecodeError] = None

    while !done && failure.isEmpty do
      if scan >= cursor.bytes.length then
        failure = Some(DecodeError.UnexpectedEnd(scan, cursor.bytes.length))
      else if visited.contains(scan) then failure = Some(DecodeError.CompressionLoop(scan))
      else
        visited += scan
        val length = cursor.bytes(scan) & 0xff
        if length == 0 then
          scan += 1
          done = true
        else if (length & 0xc0) == 0xc0 then
          if scan + 1 >= cursor.bytes.length then
            failure = Some(DecodeError.UnexpectedEnd(scan + 2, cursor.bytes.length))
          else
            val pointer = ((length & 0x3f) << 8) | (cursor.bytes(scan + 1) & 0xff)
            if pointer >= cursor.bytes.length then
              failure = Some(DecodeError.CompressionPointerOutOfBounds(pointer, cursor.bytes.length))
            else
              if resume.isEmpty then resume = Some(scan + 2)
              scan = pointer
        else if (length & 0xc0) != 0 then failure = Some(DecodeError.InvalidLabelTag(scan, length))
        else if scan + 1 + length > cursor.bytes.length then
          failure = Some(DecodeError.UnexpectedEnd(scan + 1 + length, cursor.bytes.length))
        else
          labels += cursor.bytes.slice(scan + 1, scan + 1 + length).toVector
          scan += 1 + length

    failure match
      case Some(error) => Left(error)
      case None =>
        cursor.seek(resume.getOrElse(scan)).flatMap { _ =>
          DomainName.fromLabels(labels.result()).left.map(DecodeError.InvalidName.apply)
        }

  final class Encoder(writer: WireWriter):
    private val suffixOffsets = mutable.Map.empty[Vector[Vector[Byte]], Int]

    def write(name: DomainName): Unit =
      val labels = name.labels
      val pointerIndex = labels.indices.find(index => suffixOffsets.contains(labels.drop(index)))
      val literalCount = pointerIndex.getOrElse(labels.size)
      var index = 0
      while index < literalCount do
        val suffix = labels.drop(index)
        if writer.size < 0x4000 then suffixOffsets.getOrElseUpdate(suffix, writer.size)
        val label = labels(index)
        writer.u8(label.size)
        writer.bytes(label)
        index += 1
      pointerIndex match
        case Some(found) => writer.u16(0xc000 | suffixOffsets(labels.drop(found)))
        case None => writer.u8(0)

    /** Writes a name without pointers, useful for a separately buffered RDATA field. */
    def writeUncompressed(name: DomainName): Unit =
      name.labels.foreach { label => writer.u8(label.size); writer.bytes(label) }
      writer.u8(0)
