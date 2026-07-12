package dns

/**
 * Immutable authoritative zone and query policy.
 *
 * The answer ordering follows the authoritative algorithm in
 * [[https://www.rfc-editor.org/rfc/rfc1034#section-4.3.2 RFC 1034 §4.3.2]]: delegation, exact data,
 * wildcard synthesis, CNAME processing, and negative answers. Wildcard behavior follows
 * [[https://www.rfc-editor.org/rfc/rfc4592 RFC 4592]].
 */
final class Zone private (
    val origin: DomainName,
    private val records: Map[DomainName, Vector[ResourceRecord]],
    val soa: ResourceRecord
):
  private val existingNames: Set[DomainName] = records.keysIterator.flatMap(ancestors).toSet

  /** Produces an authoritative response while preserving the request ID and question. */
  def answer(request: Message): Message =
    request.questions match
      case Vector(question) if question.recordClass != RecordClass.IN =>
        response(request, ResponseCode.Refused)
      case Vector(question) if !question.name.isSubdomainOf(origin) =>
        response(request, ResponseCode.Refused)
      case Vector(question) =>
        closestDelegation(question.name) match
          case Some(nameServers) => referral(request, nameServers)
          case None              =>
            val atName = records.get(question.name)
              .orElse(Option.when(existingNames.contains(question.name))(Vector.empty))
              .orElse(wildcardRecords(question.name))
            atName match
              case None => response(request, ResponseCode.NameError, authorities = Vector(soa))
              case Some(atName) =>
                val selected = select(atName, question.recordType)
                if selected.nonEmpty then
                  response(request, ResponseCode.NoError, answers = selected)
                else response(request, ResponseCode.NoError, authorities = Vector(soa))
      case _ => response(request, ResponseCode.FormatError)

  private def closestDelegation(name: DomainName): Option[Vector[ResourceRecord]] = ancestors(name)
    .takeWhile(_ != origin).flatMap(records.get).map(_.filter(_.recordType == RecordType.NS))
    .find(_.nonEmpty)

  private def wildcardRecords(name: DomainName): Option[Vector[ResourceRecord]] = ancestors(name)
    .drop(1).find(existingNames.contains).flatMap { closestEncloser =>
      closestEncloser.prepend("*").toOption.flatMap(records.get)
        .map(wildcard => wildcard.map(_.copy(name = name)))
    }

  private def ancestors(name: DomainName): Iterator[DomainName] =
    Iterator.iterate(Option(name))(_.flatMap(_.parent)).takeWhile(_.nonEmpty).flatten

  private def referral(request: Message, nameServers: Vector[ResourceRecord]): Message =
    val targets =
      nameServers.collect { case ResourceRecord(_, _, _, RecordData.NS(target)) => target }.toSet
    val glue = targets.toVector.flatMap(target => records.getOrElse(target, Vector.empty))
      .filter(record => record.recordType == RecordType.A || record.recordType == RecordType.AAAA)
    response(
      request,
      ResponseCode.NoError,
      authorities = nameServers,
      additionals = glue,
      authoritative = false
    )

  private def select(
      atName: Vector[ResourceRecord],
      requested: RecordType
  ): Vector[ResourceRecord] =
    if requested == RecordType.ANY then atName
    else
      val exact = atName.filter(_.recordType == requested)
      if exact.nonEmpty then exact else atName.filter(_.recordType == RecordType.CNAME)

  private def response(
      request: Message,
      code: ResponseCode,
      answers: Vector[ResourceRecord] = Vector.empty,
      authorities: Vector[ResourceRecord] = Vector.empty,
      additionals: Vector[ResourceRecord] = Vector.empty,
      authoritative: Boolean = true
  ): Message = Message(
    id = request.id,
    flags = Flags(
      response = true,
      authoritative = authoritative,
      opCode = request.flags.opCode,
      recursionDesired = request.flags.recursionDesired,
      responseCode = code
    ),
    questions = request.questions,
    answers = answers,
    authorities = authorities,
    additionals = additionals
  )

object Zone:
  enum Error derives CanEqual:
    case SoaOwnerMismatch(expected: DomainName, actual: DomainName)
    case SoaDataRequired
    case OutOfZone(name: DomainName)
    case ClassMustBeInternet(name: DomainName)
    case MultipleSoa(count: Int)
    case CnameCoexists(name: DomainName)

  /** Validates zone-wide invariants once, keeping the query path total. */
  def create(
      origin: DomainName,
      soa: ResourceRecord,
      records: Vector[ResourceRecord]
  ): Either[Error, Zone] =
    if soa.name != origin then Left(Error.SoaOwnerMismatch(origin, soa.name))
    else if soa.recordType != RecordType.SOA then Left(Error.SoaDataRequired)
    else
      val all = records :+ soa
      val soaCount = all.count(_.recordType == RecordType.SOA)
      val cnameConflict = all.groupBy(_.name).collectFirst {
        case (name, atName)
            if atName.exists(_.recordType == RecordType.CNAME) &&
              atName.exists(_.recordType != RecordType.CNAME) =>
          name
      }
      if soaCount != 1 then Left(Error.MultipleSoa(soaCount))
      else if cnameConflict.nonEmpty then Left(Error.CnameCoexists(cnameConflict.get))
      else
        all.find(record => !record.name.isSubdomainOf(origin)) match
          case Some(record) => Left(Error.OutOfZone(record.name))
          case None         =>
            all.find(_.recordClass != RecordClass.IN) match
              case Some(record) => Left(Error.ClassMustBeInternet(record.name))
              case None         => Right(new Zone(origin, (records :+ soa).groupBy(_.name), soa))
