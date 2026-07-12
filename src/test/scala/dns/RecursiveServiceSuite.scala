package dns

import java.net.InetSocketAddress

class RecursiveServiceSuite extends munit.FunSuite:
  private val root = new InetSocketAddress("192.0.2.1", 53)
  private val name = DomainName.unsafe("www.example.test.")
  private val question = Question(name, RecordType.A)

  test("RECURSIVE-SERVICE: adapts an iterative answer to client metadata") {
    val upstream = new CountingClient(finalAnswer)
    val service = serviceWith(upstream)
    val request = Message(4242, Flags(recursionDesired = true), Vector(question))

    val response = service.answer(request)

    assertEquals(response.id, 4242)
    assertEquals(response.questions, Vector(question))
    assert(response.flags.response)
    assert(response.flags.recursionAvailable)
    assert(response.flags.recursionDesired)
    assertEquals(response.answers, finalAnswer.answers)
  }

  test("RECURSIVE-CACHE: repeated questions avoid another iterative exchange") {
    val upstream = new CountingClient(finalAnswer)
    val service = serviceWith(upstream)

    val first = service.answer(Message(1, questions = Vector(question)))
    val second = service.answer(Message(2, questions = Vector(question)))

    assertEquals(first.answers, second.answers)
    assertEquals(second.id, 2)
    assertEquals(upstream.calls, 1)
  }

  test("RECURSIVE-REQUEST-SHAPE: maps invalid requests without upstream I/O") {
    val upstream = new CountingClient(finalAnswer)
    val service = serviceWith(upstream)

    val responsePacket = service.answer(Message(1, Flags(response = true), Vector(question)))
    val multiQuestion = service.answer(Message(2, questions = Vector(question, question)))
    val unsupportedClass = service
      .answer(Message(3, questions = Vector(question.copy(recordClass = RecordClass.CH))))
    val unsupportedOpcode = service
      .answer(Message(4, Flags(opCode = OpCode.Status), Vector(question)))

    assertEquals(responsePacket.flags.responseCode, ResponseCode.FormatError)
    assertEquals(multiQuestion.flags.responseCode, ResponseCode.FormatError)
    assertEquals(unsupportedClass.flags.responseCode, ResponseCode.Refused)
    assertEquals(unsupportedOpcode.flags.responseCode, ResponseCode.NotImplemented)
    assertEquals(upstream.calls, 0)
  }

  test("RECURSIVE-FAILURE: maps exhausted upstreams to SERVFAIL") {
    val upstream = new CountingClient(finalAnswer, fail = true)
    val response = serviceWith(upstream).answer(Message(1, questions = Vector(question)))

    assertEquals(response.flags.responseCode, ResponseCode.ServerFailure)
    assert(response.flags.recursionAvailable)
  }

  private final class CountingClient(response: Message, fail: Boolean = false)
      extends NameServerClient:
    var calls = 0
    override def query(
        server: InetSocketAddress,
        asked: Question
    ): Either[DnsClient.Error, Message] =
      calls += 1
      if fail then Left(DnsClient.Error.Timeout)
      else Right(response.copy(questions = Vector(asked)))

  private def serviceWith(client: NameServerClient): RecursiveService =
    new RecursiveService(
      new IterativeResolver(Vector(root), client),
      new Cache(new Ticker {
        override def nanos: Long = 0L
      })
    )

  private val finalAnswer = Message(
    99,
    Flags(response = true, authoritative = true),
    Vector(question),
    Vector(ResourceRecord(name, RecordClass.IN, 60, RecordData.ipv4("203.0.113.7")))
  )
