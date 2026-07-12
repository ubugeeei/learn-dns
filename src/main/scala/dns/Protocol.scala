package dns

import java.net.{ Inet4Address, Inet6Address, InetAddress }

/**
 * DNS operation codes from
 * [[https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1 RFC 1035 §4.1.1]].
 */
enum OpCode(val code: Int) derives CanEqual:
  case Query extends OpCode(0)
  case IQuery extends OpCode(1)
  case Status extends OpCode(2)
  case Notify extends OpCode(4)
  case Update extends OpCode(5)
  case Unknown(override val code: Int) extends OpCode(code)

object OpCode:
  def fromInt(code: Int): OpCode =
    code match
      case 0     => Query
      case 1     => IQuery
      case 2     => Status
      case 4     => Notify
      case 5     => Update
      case other => Unknown(other)

/**
 * Four-bit response code from
 * [[https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1 RFC 1035 §4.1.1]].
 *
 * Extended response codes require EDNS; see
 * [[https://www.rfc-editor.org/rfc/rfc6891#section-6.1.3 RFC 6891 §6.1.3]].
 */
enum ResponseCode(val code: Int) derives CanEqual:
  case NoError extends ResponseCode(0)
  case FormatError extends ResponseCode(1)
  case ServerFailure extends ResponseCode(2)
  case NameError extends ResponseCode(3)
  case NotImplemented extends ResponseCode(4)
  case Refused extends ResponseCode(5)
  case Unknown(override val code: Int) extends ResponseCode(code)

object ResponseCode:
  def fromInt(code: Int): ResponseCode =
    code match
      case 0     => NoError
      case 1     => FormatError
      case 2     => ServerFailure
      case 3     => NameError
      case 4     => NotImplemented
      case 5     => Refused
      case other => Unknown(other)

/**
 * Resource-record type codes from the
 * [[https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml IANA DNS Parameters registry]].
 *
 * Unknown values remain representable so decoding a newly assigned type does not destroy its
 * numeric identity.
 */
enum RecordType(val code: Int) derives CanEqual:
  case A extends RecordType(1)
  case NS extends RecordType(2)
  case CNAME extends RecordType(5)
  case SOA extends RecordType(6)
  case PTR extends RecordType(12)
  case MX extends RecordType(15)
  case TXT extends RecordType(16)
  case AAAA extends RecordType(28)
  case SRV extends RecordType(33)
  case OPT extends RecordType(41)
  case ANY extends RecordType(255)
  case Unknown(override val code: Int) extends RecordType(code)

object RecordType:
  def fromInt(code: Int): RecordType =
    code match
      case 1     => A
      case 2     => NS
      case 5     => CNAME
      case 6     => SOA
      case 12    => PTR
      case 15    => MX
      case 16    => TXT
      case 28    => AAAA
      case 33    => SRV
      case 41    => OPT
      case 255   => ANY
      case other => Unknown(other)

/**
 * DNS CLASS values from [[https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4 RFC 1035 §3.2.4]].
 */
enum RecordClass(val code: Int) derives CanEqual:
  case IN extends RecordClass(1)
  case CH extends RecordClass(3)
  case HS extends RecordClass(4)
  case ANY extends RecordClass(255)
  case Unknown(override val code: Int) extends RecordClass(code)

object RecordClass:
  def fromInt(code: Int): RecordClass =
    code match
      case 1     => IN
      case 3     => CH
      case 4     => HS
      case 255   => ANY
      case other => Unknown(other)

/**
 * Header flags, excluding the transaction identifier and section counts.
 *
 * Every field maps to the bit diagram in
 * [[https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1 RFC 1035 §4.1.1]]. AD and CD were later
 * defined by [[https://www.rfc-editor.org/rfc/rfc4035#section-3.2 RFC 4035 §3.2]].
 */
final case class Flags(
    response: Boolean = false,
    opCode: OpCode = OpCode.Query,
    authoritative: Boolean = false,
    truncated: Boolean = false,
    recursionDesired: Boolean = true,
    recursionAvailable: Boolean = false,
    authenticatedData: Boolean = false,
    checkingDisabled: Boolean = false,
    responseCode: ResponseCode = ResponseCode.NoError
)

/**
 * One DNS question: owner name, requested type, and namespace class.
 *
 * The wire layout is specified by
 * [[https://www.rfc-editor.org/rfc/rfc1035#section-4.1.2 RFC 1035 §4.1.2]].
 */
final case class Question(
    name: DomainName,
    recordType: RecordType,
    recordClass: RecordClass = RecordClass.IN
)

/**
 * Typed resource-record data.
 *
 * Name-bearing cases use [[DomainName]] rather than storing their compressed wire bytes.
 * [[RecordData.Unknown]] preserves unrecognized RDATA exactly for forward-compatible proxies and
 * diagnostic tooling.
 */
enum RecordData derives CanEqual:
  case A(address: Inet4Address)
  case AAAA(address: Inet6Address)
  case NS(name: DomainName)
  case CName(name: DomainName)
  case Ptr(name: DomainName)
  case MX(preference: Int, exchange: DomainName)
  case TXT(chunks: Vector[Vector[Byte]])
  case SOA(
      primaryNameServer: DomainName,
      responsibleMailbox: DomainName,
      serial: Long,
      refresh: Long,
      retry: Long,
      expire: Long,
      minimum: Long
  )
  case SRV(priority: Int, weight: Int, port: Int, target: DomainName)
  case Unknown(recordType: RecordType, bytes: Vector[Byte])

object RecordData:
  def ipv4(value: String): RecordData.A = A(InetAddress.getByName(value).asInstanceOf[Inet4Address])

  def ipv6(value: String): RecordData.AAAA = AAAA(
    InetAddress.getByName(value).asInstanceOf[Inet6Address]
  )

/**
 * A complete DNS resource record.
 *
 * TTL is stored as the unsigned 32-bit wire value described in
 * [[https://www.rfc-editor.org/rfc/rfc1035#section-3.2.1 RFC 1035 §3.2.1]]. [[recordType]] is
 * derived from [[data]], preventing contradictory type/data pairs from being constructed.
 */
final case class ResourceRecord(
    name: DomainName,
    recordClass: RecordClass,
    ttl: Long,
    data: RecordData
):
  require(ttl >= 0 && ttl <= 0xffffffffL, s"TTL out of unsigned 32-bit range: $ttl")

  def recordType: RecordType =
    data match
      case _: RecordData.A           => RecordType.A
      case _: RecordData.AAAA        => RecordType.AAAA
      case _: RecordData.NS          => RecordType.NS
      case _: RecordData.CName       => RecordType.CNAME
      case _: RecordData.Ptr         => RecordType.PTR
      case _: RecordData.MX          => RecordType.MX
      case _: RecordData.TXT         => RecordType.TXT
      case _: RecordData.SOA         => RecordType.SOA
      case _: RecordData.SRV         => RecordType.SRV
      case value: RecordData.Unknown => value.recordType

/**
 * A DNS message as four ordered sections.
 *
 * Section order and count semantics follow
 * [[https://www.rfc-editor.org/rfc/rfc1035#section-4.1 RFC 1035 §4.1]]. The ID is validated as an
 * unsigned 16-bit value at construction.
 */
final case class Message(
    id: Int,
    flags: Flags = Flags(),
    questions: Vector[Question] = Vector.empty,
    answers: Vector[ResourceRecord] = Vector.empty,
    authorities: Vector[ResourceRecord] = Vector.empty,
    additionals: Vector[ResourceRecord] = Vector.empty
):
  require(id >= 0 && id <= 0xffff, s"ID out of unsigned 16-bit range: $id")
