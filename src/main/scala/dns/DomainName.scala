package dns

/** An absolute DNS domain name represented as decoded labels.
  *
  * The invariants come from
  * [[https://www.rfc-editor.org/rfc/rfc1035#section-2.3.4 RFC 1035 §2.3.4]]:
  * a label occupies at most 63 octets and the complete wire name at most 255.
  * Labels are kept as octets because DNS names are not intrinsically Unicode.
  * Use [[DomainName.fromString]] for the presentation form used in this project.
  */
final class DomainName private (private val rawLabels: Vector[Vector[Byte]]):
  /** Copies the labels so callers cannot mutate the name through an array. */
  def labels: Vector[Vector[Byte]] = rawLabels

  /** True for the root name (`.`). */
  def isRoot: Boolean = rawLabels.isEmpty

  /** Number of octets in the uncompressed wire representation. */
  def wireLength: Int = rawLabels.foldLeft(1)((n, label) => n + 1 + label.size)

  /** Returns a child name by prepending one label. */
  def prepend(label: String): Either[DomainName.Error, DomainName] =
    DomainName.fromLabels(Vector(DomainName.asciiBytes(label)) ++ rawLabels)

  /** Whether this name is at or below `zone`, using ASCII case-insensitive DNS matching. */
  def isSubdomainOf(zone: DomainName): Boolean =
    rawLabels.size >= zone.rawLabels.size &&
      rawLabels.takeRight(zone.rawLabels.size).lazyZip(zone.rawLabels).forall(DomainName.labelsEqual)

  override def equals(other: Any): Boolean = other match
    case that: DomainName =>
      rawLabels.size == that.rawLabels.size &&
        rawLabels.lazyZip(that.rawLabels).forall(DomainName.labelsEqual)
    case _ => false

  override def hashCode: Int =
    rawLabels.foldLeft(1)((hash, label) => 31 * hash + DomainName.folded(label).hashCode)

  override def toString: String =
    if isRoot then "."
    else rawLabels.map(DomainName.renderLabel).mkString(".") + "."

object DomainName:
  /** Why construction of a domain name failed. */
  enum Error derives CanEqual:
    case EmptyLabel
    case LabelTooLong(length: Int)
    case NameTooLong(length: Int)
    case NonAscii(character: Char)

  val Root: DomainName = new DomainName(Vector.empty)

  /** Parses an absolute or root presentation name.
    *
    * A missing final dot is accepted as a convenience but still produces an
    * absolute name. Backslash escaping and IDNA conversion deliberately belong
    * in a higher presentation layer; see
    * [[https://www.rfc-editor.org/rfc/rfc4343 RFC 4343]] for DNS case rules.
    */
  def fromString(value: String): Either[Error, DomainName] =
    if value == "." || value.isEmpty then Right(Root)
    else
      val text = value.stripSuffix(".")
      text.find(_ > 0x7f) match
        case Some(character) => Left(Error.NonAscii(character))
        case None => fromLabels(text.split("\.", -1).toVector.map(asciiBytes))

  def fromLabels(labels: Vector[Vector[Byte]]): Either[Error, DomainName] =
    labels.find(_.isEmpty) match
      case Some(_) => Left(Error.EmptyLabel)
      case None =>
        labels.find(_.size > 63) match
          case Some(label) => Left(Error.LabelTooLong(label.size))
          case None =>
            val length = labels.foldLeft(1)((n, label) => n + 1 + label.size)
            if length > 255 then Left(Error.NameTooLong(length))
            else Right(new DomainName(labels))

  def unsafe(value: String): DomainName =
    fromString(value).fold(error => throw IllegalArgumentException(error.toString), identity)

  private[dns] def asciiBytes(value: String): Vector[Byte] =
    value.iterator.map(_.toByte).toVector

  private def folded(label: Vector[Byte]): Vector[Byte] = label.map { byte =>
    val unsigned = byte & 0xff
    if unsigned >= 'A' && unsigned <= 'Z' then (unsigned + 32).toByte else byte
  }

  private def labelsEqual(left: Vector[Byte], right: Vector[Byte]): Boolean =
    folded(left) == folded(right)

  private def renderLabel(label: Vector[Byte]): String =
    label.iterator.map(byte => (byte & 0xff).toChar).mkString
