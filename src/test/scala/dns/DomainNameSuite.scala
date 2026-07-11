package dns

class DomainNameSuite extends munit.FunSuite:
  test("root has the one-octet wire representation") {
    assertEquals(DomainName.Root.toString, ".")
    assertEquals(DomainName.Root.wireLength, 1)
  }

  test("presentation parser canonicalizes absolute spelling") {
    val name = DomainName.fromString("www.example.com").toOption.get
    assertEquals(name.toString, "www.example.com.")
    assertEquals(name.wireLength, 17)
  }

  test("DNS comparison is ASCII case insensitive") {
    assertEquals(DomainName.unsafe("WWW.Example.COM."), DomainName.unsafe("www.example.com."))
    assertEquals(DomainName.unsafe("WWW.Example.COM.").hashCode, DomainName.unsafe("www.example.com.").hashCode)
  }

  test("subdomain comparison follows label boundaries") {
    val name = DomainName.unsafe("www.example.com.")
    assert(name.isSubdomainOf(DomainName.unsafe("example.com.")))
    assert(!name.isSubdomainOf(DomainName.unsafe("ample.com.")))
    assert(name.isSubdomainOf(DomainName.Root))
  }

  test("rejects empty and oversized labels") {
    assertEquals(DomainName.fromString("a..example."), Left(DomainName.Error.EmptyLabel))
    assertEquals(
      DomainName.fromString("a" * 64 + "."),
      Left(DomainName.Error.LabelTooLong(64))
    )
  }

  test("rejects names beyond the 255 octet wire limit") {
    val value = Vector.fill(4)("a" * 63).mkString(".") + "."
    assertEquals(DomainName.fromString(value), Left(DomainName.Error.NameTooLong(257)))
  }

  test("rejects non-ASCII presentation input instead of corrupting it") {
    assertEquals(DomainName.fromString("café.example."), Left(DomainName.Error.NonAscii('é')))
  }
