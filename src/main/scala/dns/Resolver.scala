package dns

/** Effect boundary for sending a DNS message to one upstream server.
  *
  * Keeping transport behind this small interface lets resolution policy be
  * tested with packet fixtures rather than sockets.
  */
trait Exchange[F[_]]:
  def apply(request: Message): F[Message]

/** Cache-through stub resolution policy.
  *
  * This is the first runnable resolver milestone: it handles one-question
  * queries and caching while delegating recursion to an upstream. The later
  * iterative resolver can implement the same public shape by replacing the
  * exchange policy with referral walking.
  */
final class CachingResolver(cache: Cache, exchange: Exchange[[value] =>> Either[DnsClient.Error, value]]):
  def resolve(request: Message): Either[DnsClient.Error, Message] =
    request.questions match
      case Vector(question) =>
        cache.get(question) match
          case Some(cached) => Right(forRequest(request, cached))
          case None =>
            exchange(request).map { response =>
              cache.put(question, response): Unit
              response
            }
      case _ => exchange(request)

  private def forRequest(request: Message, cached: Message): Message =
    cached.copy(
      id = request.id,
      flags = cached.flags.copy(recursionDesired = request.flags.recursionDesired),
      questions = request.questions
    )
