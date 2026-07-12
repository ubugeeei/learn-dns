package dns

class IpAddressSuite extends munit.FunSuite:
  test("IPV4-LITERAL: accepts exactly four decimal octets") {
    assertEquals(IpAddress.ipv4("192.0.2.1").toOption.map(_.getHostAddress), Some("192.0.2.1"))
    Vector("example.com", "192.0.2", "192.0.2.256", "192.0..1", "+1.2.3.4").foreach { value =>
      assertEquals(IpAddress.ipv4(value), Left(IpAddress.Error.InvalidIpv4(value)))
    }
  }

  test("IPV6-LITERAL: requires an IPv6 literal and rejects scoped addresses") {
    assert(IpAddress.ipv6("2001:db8::1").isRight)
    Vector("example.com", "192.0.2.1", "fe80::1%en0", "2001:db8:::1").foreach { value =>
      assertEquals(IpAddress.ipv6(value), Left(IpAddress.Error.InvalidIpv6(value)))
    }
  }
