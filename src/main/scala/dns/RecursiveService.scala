package dns

/**
 * DNS message policy that combines iterative resolution and TTL caching.
 *
 * The service validates the request shape, preserves client transaction metadata, advertises
 * recursion availability, and maps internal resolver failures to protocol response codes without
 * leaking transport details. It can be passed directly to [[DnsServer.start]].
 */
final class RecursiveService(resolver: IterativeResolver, cache: Cache):
  /** Answers one standard QUERY according to RFC 1034 resolver semantics. */
  def answer(request: Message): Message =
    if request.flags.response then error(request, ResponseCode.FormatError)
    else if request.flags.opCode != OpCode.Query then error(request, ResponseCode.NotImplemented)
    else
      request.questions match
        case Vector(question) if question.recordClass == RecordClass.IN =>
          val resolved = cache.get(question).toRight(()).orElse {
            resolver.resolve(question).left.map(_ => ()).map { response =>
              cache.put(question, response): Unit
              response
            }
          }
          resolved.fold(
            _ => error(request, ResponseCode.ServerFailure),
            response => forClient(request, response)
          )
        case Vector(_) => error(request, ResponseCode.Refused)
        case _         => error(request, ResponseCode.FormatError)

  private def forClient(request: Message, response: Message): Message = response.copy(
    id = request.id,
    flags = response.flags.copy(
      response = true,
      recursionDesired = request.flags.recursionDesired,
      recursionAvailable = true
    ),
    questions = request.questions,
    additionals = response.additionals.filterNot(_.recordType == RecordType.OPT)
  )

  private def error(request: Message, code: ResponseCode): Message = Message(
    id = request.id,
    flags = Flags(
      response = true,
      opCode = request.flags.opCode,
      recursionDesired = request.flags.recursionDesired,
      recursionAvailable = true,
      responseCode = code
    ),
    questions = request.questions
  )
