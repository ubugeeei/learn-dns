package dns

import java.net.InetSocketAddress

/** Sends one question directly to one name server without requesting recursion. */
trait NameServerClient:
  def query(server: InetSocketAddress, question: Question): Either[DnsClient.Error, Message]

object NameServerClient:
  /** Network implementation backed by the UDP/TCP stub transport. */
  val network: NameServerClient =
    new NameServerClient:
      override def query(
          server: InetSocketAddress,
          question: Question
      ): Either[DnsClient.Error, Message] = new DnsClient(server)
        .query(question.name, question.recordType, recursionDesired = false)

/**
 * A bounded iterative resolver that follows referrals from configured roots.
 *
 * The state machine implements the high-level algorithm in
 * [[https://www.rfc-editor.org/rfc/rfc1034#section-5.3.3 RFC 1034 §5.3.3]]. It accepts only
 * in-bailiwick A/AAAA glue for a referral, follows CNAME aliases, detects repeated aliases and
 * delegations, and applies global query limits. When a referral legitimately omits glue, the
 * resolver performs a subsidiary address lookup while retaining the same budgets and dependency
 * loop detector.
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
    if question.recordClass != RecordClass.IN then
      Left(Error.UnsupportedClass(question.recordClass))
    else resolveQuestion(question, new Budget(config), Set.empty)

  private def resolveQuestion(
      question: Question,
      budget: Budget,
      resolvingNameServers: Set[DomainName]
  ): Either[Error, Message] = walk(
    State(question, roots, Vector.empty, Set(question.name), Set.empty, resolvingNameServers),
    budget
  )

  private def walk(state: State, budget: Budget): Either[Error, Message] = queryAny(
    state.servers,
    state.question,
    budget
  ).flatMap(response => interpret(state, response, budget))

  private def interpret(state: State, response: Message, budget: Budget): Either[Error, Message] =
    response.flags.responseCode match
      case ResponseCode.NameError => Right(withAliases(response, state.aliases))
      case ResponseCode.NoError   =>
        val exact = response.answers.filter(record =>
          record.name == state.question.name && record.recordType == state.question.recordType
        )
        if exact.nonEmpty then Right(withAliases(response, state.aliases))
        else
          cnameTarget(response, state.question.name) match
            case Some((record, target)) => followAlias(state, record, target, budget)
            case None                   => followReferral(state, response, budget)
      case code => Left(Error.ServerResponse(code))

  private def followAlias(
      state: State,
      record: ResourceRecord,
      target: DomainName,
      budget: Budget
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
        ),
        budget
      )

  private def followReferral(
      state: State,
      response: Message,
      budget: Budget
  ): Either[Error, Message] =
    closestReferral(state.question.name, response.authorities) match
      case None                            => Right(withAliases(response, state.aliases))
      case Some((delegation, nameServers)) =>
        if state.visitedDelegations.contains(delegation) then Left(Error.ReferralLoop(delegation))
        else
          for
            _ <- budget.consumeReferral()
            glue = glueServers(delegation, nameServers, response.additionals)
            servers <-
              if glue.nonEmpty then Right(glue)
              else resolveNameServerAddresses(nameServers, state, budget)
            result <- walk(
              state.copy(
                servers = servers,
                visitedDelegations = state.visitedDelegations + delegation
              ),
              budget
            )
          yield result

  private def resolveNameServerAddresses(
      nameServers: Vector[DomainName],
      state: State,
      budget: Budget
  ): Either[Error, Vector[InetSocketAddress]] = nameServers.foldLeft(
    Right(Vector.empty): Either[Error, Vector[InetSocketAddress]]
  ) { (accumulated, nameServer) =>
    accumulated.flatMap { addresses =>
      if state.resolvingNameServers.contains(nameServer) then
        Left(Error.NameServerDependencyLoop(nameServer))
      else
        resolveQuestion(
          Question(nameServer, RecordType.A),
          budget,
          state.resolvingNameServers + nameServer
        ).map { response =>
          val resolved = response.answers.collect {
            case ResourceRecord(`nameServer`, RecordClass.IN, _, RecordData.A(address)) =>
              new InetSocketAddress(address, 53)
          }
          addresses ++ resolved
        }
    }
  }.flatMap(addresses =>
    Either.cond(addresses.nonEmpty, addresses.distinct, Error.MissingGlue(nameServers))
  )

  private def queryAny(
      servers: Vector[InetSocketAddress],
      question: Question,
      budget: Budget
  ): Either[Error, Message] =
    val attempts = servers.iterator
    var response: Option[Message] = None
    var failure: Option[Error] = None
    while attempts.hasNext && response.isEmpty && failure.isEmpty do
      budget.consumeQuery() match
        case Left(error) => failure = Some(error)
        case Right(_)    =>
          client.query(attempts.next(), question).foreach(value => response = Some(value))
    response.toRight(failure.getOrElse(Error.AllServersFailed(servers)))

  private def closestReferral(
      questionName: DomainName,
      authorities: Vector[ResourceRecord]
  ): Option[(DomainName, Vector[DomainName])] =
    authorities.collect { case ResourceRecord(owner, _, _, RecordData.NS(target)) =>
      owner -> target
    }.groupMap(_._1)(_._2).filter((owner, _) => questionName.isSubdomainOf(owner)).toVector
      .sortBy((owner, _) => -owner.labels.size).headOption

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
  ): Option[(ResourceRecord, DomainName)] = response.answers.collectFirst {
    case record @ ResourceRecord(`owner`, _, _, RecordData.CName(target)) => record -> target
  }

  private def withAliases(message: Message, aliases: Vector[ResourceRecord]): Message = message
    .copy(answers = aliases ++ message.answers)

object IterativeResolver:
  final case class Config(maxQueries: Int = 64, maxReferrals: Int = 32, maxCnameDepth: Int = 16):
    require(maxQueries > 0)
    require(maxReferrals > 0)
    require(maxCnameDepth > 0)

  enum Error derives CanEqual:
    case UnsupportedClass(recordClass: RecordClass)
    case AllServersFailed(servers: Vector[InetSocketAddress])
    case ServerResponse(code: ResponseCode)
    case MissingGlue(nameServers: Vector[DomainName])
    case NameServerDependencyLoop(name: DomainName)
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
      resolvingNameServers: Set[DomainName]
  )

  private final class Budget(config: Config):
    private var queries = 0
    private var referrals = 0

    def consumeQuery(): Either[Error, Unit] =
      if queries >= config.maxQueries then Left(Error.QueryBudgetExceeded(config.maxQueries))
      else
        queries += 1
        Right(())

    def consumeReferral(): Either[Error, Unit] =
      if referrals >= config.maxReferrals then
        Left(Error.ReferralBudgetExceeded(config.maxReferrals))
      else
        referrals += 1
        Right(())
