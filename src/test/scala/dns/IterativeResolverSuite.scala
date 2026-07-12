package dns

import java.net.InetSocketAddress

class IterativeResolverSuite extends munit.FunSuite:
  private val root = socket("192.0.2.1")
  private val childServer = socket("192.0.2.53")
  private val question = Question(name("www.example.test."), RecordType.A)

  test("ITERATIVE-REFERRAL: follows in-bailiwick glue from root to an answer") {
    val scenario = Scenario(
      root -> referral(
        delegation = name("example.test."),
        serverName = name("ns.example.test."),
        glueAddress = "192.0.2.53"
      ),
      childServer -> answer(question.name, "203.0.113.7")
    )

    val result = new IterativeResolver(Vector(root), scenario).resolve(question)

    assertEquals(
      result.toOption.flatMap(_.answers.headOption),
      Some(a(question.name, "203.0.113.7"))
    )
    assertEquals(scenario.visited, Vector(root, childServer))
  }

  test("ITERATIVE-BAILIWICK: ignores unrelated additional addresses") {
    val delegation = name("example.test.")
    val serverName = name("ns.example.test.")
    val maliciousName = name("ns.attacker.invalid.")
    val response = referral(delegation, serverName, "192.0.2.53")
      .copy(additionals = Vector(a(maliciousName, "192.0.2.66"), a(serverName, "192.0.2.53")))
    val scenario = Scenario(root -> response, childServer -> answer(question.name, "203.0.113.7"))

    assert(new IterativeResolver(Vector(root), scenario).resolve(question).isRight)
    assertEquals(scenario.visited, Vector(root, childServer))
  }

  test("ITERATIVE-MISSING-GLUE: resolves an out-of-bailiwick name-server address") {
    val delegation = name("example.test.")
    val externalServer = name("ns.provider.invalid.")
    val externalAddress = socket("192.0.2.70")
    val response = Message(
      id = 1,
      flags = Flags(response = true),
      questions = Vector(question),
      authorities = Vector(ns(delegation, externalServer)),
      additionals = Vector(a(externalServer, "192.0.2.66"))
    )
    val scenario = Scenario(
      root -> response,
      root -> answer(externalServer, "192.0.2.70"),
      externalAddress -> answer(question.name, "203.0.113.9")
    )

    assertEquals(
      new IterativeResolver(Vector(root), scenario).resolve(question).toOption
        .flatMap(_.answers.headOption),
      Some(a(question.name, "203.0.113.9"))
    )
    assertEquals(scenario.visited, Vector(root, root, externalAddress))
  }

  test("ITERATIVE-RETRY: tries the next server after a timeout") {
    val unavailable = socket("192.0.2.2")
    val scenario = Scenario(root -> answer(question.name, "203.0.113.10"))

    val result = new IterativeResolver(Vector(unavailable, root), scenario).resolve(question)

    assert(result.isRight)
    assertEquals(scenario.visited, Vector(unavailable, root))
  }

  test("ITERATIVE-CNAME: restarts from roots and preserves the alias chain") {
    val alias = name("alias.example.test.")
    val cname = ResourceRecord(question.name, RecordClass.IN, 60, RecordData.CName(alias))
    val scenario = Scenario(
      root -> Message(
        id = 1,
        flags = Flags(response = true),
        questions = Vector(question),
        answers = Vector(cname)
      ),
      root -> answer(alias, "203.0.113.8")
    )

    val result = new IterativeResolver(Vector(root), scenario).resolve(question).toOption.get

    assertEquals(result.answers, Vector(cname, a(alias, "203.0.113.8")))
  }

  test("ITERATIVE-CNAME-LOOP: terminates repeated aliases") {
    val alias = name("alias.example.test.")
    val scenario = Scenario(
      root -> cnameAnswer(question.name, alias),
      root -> cnameAnswer(alias, question.name)
    )

    assertEquals(
      new IterativeResolver(Vector(root), scenario).resolve(question),
      Left(IterativeResolver.Error.CnameLoop(question.name))
    )
  }

  private final class Scenario private (private var responses: List[(InetSocketAddress, Message)])
      extends NameServerClient:
    private var visits = Vector.empty[InetSocketAddress]
    def visited: Vector[InetSocketAddress] = visits

    override def query(
        server: InetSocketAddress,
        asked: Question
    ): Either[DnsClient.Error, Message] =
      visits :+= server
      responses match
        case (`server`, response) :: tail =>
          responses = tail
          Right(response.copy(questions = Vector(asked)))
        case _ => Left(DnsClient.Error.Timeout)

  private object Scenario:
    def apply(responses: (InetSocketAddress, Message)*): Scenario = new Scenario(responses.toList)

  private def referral(
      delegation: DomainName,
      serverName: DomainName,
      glueAddress: String
  ): Message = Message(
    id = 1,
    flags = Flags(response = true),
    questions = Vector(question),
    authorities = Vector(ns(delegation, serverName)),
    additionals = Vector(a(serverName, glueAddress))
  )

  private def answer(owner: DomainName, address: String): Message = Message(
    id = 1,
    flags = Flags(response = true, authoritative = true),
    questions = Vector(question.copy(name = owner)),
    answers = Vector(a(owner, address))
  )

  private def cnameAnswer(owner: DomainName, target: DomainName): Message = Message(
    id = 1,
    flags = Flags(response = true, authoritative = true),
    questions = Vector(question.copy(name = owner)),
    answers = Vector(ResourceRecord(owner, RecordClass.IN, 60, RecordData.CName(target)))
  )

  private def ns(owner: DomainName, target: DomainName): ResourceRecord = ResourceRecord(
    owner,
    RecordClass.IN,
    300,
    RecordData.NS(target)
  )

  private def a(owner: DomainName, address: String): ResourceRecord = ResourceRecord(
    owner,
    RecordClass.IN,
    60,
    RecordData.ipv4(address)
  )

  private def name(value: String): DomainName = DomainName.unsafe(value)
  private def socket(address: String): InetSocketAddress = new InetSocketAddress(address, 53)
