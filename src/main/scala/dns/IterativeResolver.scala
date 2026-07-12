package dns

import java.net.InetSocketAddress

/** Sends one question directly to one name server without requesting recursion. */
trait NameServerClient:
  def query(
      server: InetSocketAddress,
      question: Question
  ): Either[DnsClient.Error, Message]

object NameServerClient:
  /** Network implementation backed by the UDP/TCP stub transport. */
  val network: NameServerClient = new NameServerClient:
    override def query(
        server: InetSocketAddress,
        question: Question
    ): Either[DnsClient.Error, Message] =
      new DnsClient(server).query(
        question.name,
        question.recordType,
        recursionDesired = false
      )

/** A bounded iterative resolver that follows referrals from configured roots.
  *
  * The state machine implements the high-level algorithm in
  * [[https://www.rfc-editor.org/rfc/rfc1034#section-5.3.3 RFC 1034 §5.3.3]]. It
  * accepts only in-bailiwick A/AAAA glue for a referral, follows CNAME aliases,
  * detects repeated aliases and delegations, and applies global query limits.
  *
  * This milestone deliberately reports [[IterativeResolver.Error.MissingGlue]]
  * instead of recursively resolving out-of-bailiwick name-server addresses.
  * That behavior is explicit rather than silently trusting unrelated additional
  * records.
  */
final class IterativeResolver(
    roots: Vector[InetSocketAddress],
    client: NameServerClient,
    config: IterativeResolver.Config = IterativeResolver.Config()
):
  import IterativeResolver.*

  require(roots.nonEmpty, "at least one root server is required")

  /** Resolves one Internet-class question from the configured root hints. */
  def resolve(question: Question): Either[Error, Message] =
    if question.recordClass != RecordClass.IN then Left(Error.UnsupportedClass(question.recordClass))
    else walk(State(question, roots, Vector.empty, Set(question.name), Set.empty, 0, 0))

  private def walk(state: State): Either[Error, Message] =
    if state.queries >= config.maxQueries then Left(Error.QueryBudgetExceeded(config.maxQueries))
    else if state.referrals >= config.maxReferrals then
      Left(Error.ReferralBudgetExceeded(config.maxReferrals))
    else
      queryAny(state.servers, state.question).flatMap { response =>
        val nextState = state.copy(queries = state.queries + 1)
        interpret(nextState, response)
      }

  private def interpret(state: State, response: Message): Either[Error, Message] =
    response.flags.responseCode match
      case ResponseCode.NameError => Right(withAliases(response, state.aliases))
      case ResponseCode.NoError =>
        val exact = response.answers.filter(record =>
          record.name == state.question.name && record.recordType == state.question.recordType
        )
        if exact.nonEmpty then Right(withAliases(response, state.aliases))
        else cnameTarget(response, state.question.name) match
          case Some((record, target)) => followAlias(state, record, target)
          case None                   => followReferral(state, response)
      case code => Left(Error.ServerResponse(code))

  private def followAlias(
      state: State,
      record: ResourceRecord,
      target: DomainName
  ): Either[Error, Message] =
    if state.aliases.size >= config.maxCnameDepth then
      Left(Error.CnameBudgetExceeded(config.maxCnameDepth))
    else if state.visitedNames.contains(target) then Left(Error.CnameLoop(target))
    else
      walk(
        state.copy(
          question = state.question.copy(name = target),
          servers = roots,
          aliases = state.aliases :+ record,
          visitedNames = state.visitedNames + target
        )
      )

  private def followReferral(state: State, response: Message): Either[Error, Message] =
    closestReferral(state.question.name, response.authorities) match
      case None => Right(withAliases(response, state.aliases))
      case Some((delegation, nameServers)) =>
        if state.visitedDelegations.contains(delegation) then
          Left(Error.ReferralLoop(delegation))
        else
          val servers = glueServers(delegation, nameServers, response.additionals)
          if servers.isEmpty then Left(Error.MissingGlue(delegation, nameServers))
          else
            walk(
              state.copy(
                servers = servers,
                visitedDelegations = state.visitedDelegations + delegation,
                referrals = state.referrals + 1
              )
            )

  private def queryAny(
      servers: Vector[InetSocketAddress],
      question: Question
  ): Either[Error, Message] =
    servers.iterator
      .map(server => client.query(server, question))
      .collectFirst { case Right(response) => Right(response) }
      .getOrElse(Left(Error.AllServersFailed(servers)))

  private def closestReferral(
      questionName: DomainName,
      authorities: Vector[ResourceRecord]
  ): Option[(DomainName, Vector[DomainName])] =
    authorities
      .collect { case ResourceRecord(owner, _, _, RecordData.NS(target)) => owner -> target }
      .groupMap(_._1)(_._2)
      .filter((owner, _) => questionName.isSubdomainOf(owner))
      .toVector
      .sortBy((owner, _) => -owner.labels.size)
      .headOption

  private def glueServers(
      delegation: DomainName,
      nameServers: Vector[DomainName],
      additionals: Vector[ResourceRecord]
  ): Vector[InetSocketAddress] =
    val eligible = nameServers.filter(_.isSubdomainOf(delegation)).toSet
    additionals.flatMap {
      case ResourceRecord(owner, RecordClass.IN, _, RecordData.A(address))
          if eligible.contains(owner) =>
        Some(new InetSocketAddress(address, 53))
      case ResourceRecord(owner, RecordClass.IN, _, RecordData.AAAA(address))
          if eligible.contains(owner) =>
        Some(new InetSocketAddress(address, 53))
      case _ => None
    }.distinct

  private def cnameTarget(
      response: Message,
      owner: DomainName
  ): Option[(ResourceRecord, DomainName)] =
    response.answers.collectFirst {
      case record @ ResourceRecord(`owner`, _, _, RecordData.CName(target)) => record -> target
    }

  private def withAliases(message: Message, aliases: Vector[ResourceRecord]): Message =
    message.copy(answers = aliases ++ message.answers)

object IterativeResolver:
  final case class Config(
      maxQueries: Int = 64,
      maxReferrals: Int = 32,
      maxCnameDepth: Int = 16
  ):
    require(maxQueries > 0)
    require(maxReferrals > 0)
    require(maxCnameDepth > 0)

  enum Error derives CanEqual:
    case UnsupportedClass(recordClass: RecordClass)
    case AllServersFailed(servers: Vector[InetSocketAddress])
    case ServerResponse(code: ResponseCode)
    case MissingGlue(delegation: DomainName, nameServers: Vector[DomainName])
    case ReferralLoop(delegation: DomainName)
    case CnameLoop(name: DomainName)
    case QueryBudgetExceeded(limit: Int)
    case ReferralBudgetExceeded(limit: Int)
    case CnameBudgetExceeded(limit: Int)

  private final case class State(
      question: Question,
      servers: Vector[InetSocketAddress],
      aliases: Vector[ResourceRecord],
      visitedNames: Set[DomainName],
      visitedDelegations: Set[DomainName],
      queries: Int,
      referrals: Int
  )
