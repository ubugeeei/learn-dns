package dns

import org.scalacheck.Gen
import org.scalacheck.Prop.forAll

/**
 * Executable protocol laws shared by every concrete packet example.
 *
 * Example tests document packets we know. Properties document invariants that must survive inputs
 * we did not think to write by hand.
 */
class ProtocolProperties extends munit.ScalaCheckSuite:
  private val label: Gen[String] =
    for
      length <- Gen.choose(1, 20)
      characters <- Gen.listOfN(length, Gen.alphaNumChar)
    yield characters.mkString

  private val domainName: Gen[DomainName] =
    for
      count <- Gen.choose(0, 5)
      labels <- Gen.listOfN(count, label)
    yield if labels.isEmpty then DomainName.Root else DomainName.unsafe(labels.mkString(".") + ".")

  private val recordType: Gen[RecordType] = Gen.oneOf(
    RecordType.A,
    RecordType.AAAA,
    RecordType.NS,
    RecordType.CNAME,
    RecordType.MX,
    RecordType.TXT
  )

  property("DOMAIN-NAME-CASE: ASCII case changes preserve DNS identity") {
    forAll(domainName) { name =>
      val swapped = name.toString.map { character =>
        if character.isLower then character.toUpper
        else if character.isUpper then character.toLower
        else character
      }
      assertEquals(DomainName.fromString(swapped), Right(name))
    }
  }

  property("DOMAIN-NAME-WIRE: validated names always fit the RFC 1035 limit") {
    forAll(domainName) { name =>
      assert(name.wireLength >= 1)
      assert(name.wireLength <= 255)
      assert(name.labels.forall(label => label.nonEmpty && label.size <= 63))
    }
  }

  property("MESSAGE-ROUNDTRIP: questions survive encoding and compression") {
    forAll(domainName, recordType, Gen.choose(0, 0xffff)) { (name, kind, id) =>
      val message = Message(
        id = id,
        flags = Flags(recursionDesired = true),
        questions = Vector(Question(name, kind), Question(name, RecordType.AAAA))
      )
      assertEquals(MessageCodec.decode(MessageCodec.encode(message)), Right(message))
    }
  }

  property("DECODER-TOTALITY: arbitrary bounded bytes return a value without throwing") {
    val byte = Gen.choose(Byte.MinValue.toInt, Byte.MaxValue.toInt).map(_.toByte)
    val packet = Gen.choose(0, 2048).flatMap(length => Gen.containerOfN[Array, Byte](length, byte))
    forAll(packet) { bytes =>
      val result = MessageCodec.decode(bytes)
      assert(result.isLeft || result.isRight)
    }
  }
