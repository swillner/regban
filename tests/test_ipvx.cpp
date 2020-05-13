#define DOCTEST_CONFIG_SUPER_FAST_ASSERTS
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
// make sure doctest comes before including tested classes

#include <sstream>

#include "IPvX.h"

using regban::IPvX;

std::string to_string(IPvX ip) {
    std::ostringstream ss;
    ss << ip;
    return ss.str();
}

TEST_CASE("ipv4") {
    SUBCASE("output") {
        {
            std::ostringstream ss;
            ss << IPvX::Formatter(0x12345678);
            CHECK(ss.str() == "18.52.86.120");
        }
        CHECK(to_string(0x12345678) == "18.52.86.120");
        CHECK(to_string(0x1234567) == "1.35.69.103");
        CHECK(to_string(0x123456) == "0.18.52.86");
        CHECK(to_string(0x12345) == "0.1.35.69");
        CHECK(to_string(0x1234) == "0.0.18.52");
        CHECK(to_string(0x123) == "0.0.1.35");
        CHECK(to_string(0x12) == "0.0.0.18");
        CHECK(to_string(0x1) == "0.0.0.1");
        CHECK(to_string(0) == "0.0.0.0");
    }

    SUBCASE("parsing") {
        CHECK(0x12345678 == IPvX::parse("18.52.86.120"));
        CHECK(0x1234567 == IPvX::parse("1.35.69.103"));
        CHECK(0x123456 == IPvX::parse("0.18.52.86"));
        CHECK(0x12345 == IPvX::parse("0.1.35.69"));
        CHECK(0x1234 == IPvX::parse("0.0.18.52"));
        CHECK(0x123 == IPvX::parse("0.0.1.35"));
        CHECK(0x12 == IPvX::parse("0.0.0.18"));
        CHECK(0x1 == IPvX::parse("0.0.0.1"));
        CHECK(0x12345678 == IPvX::parse("18.52.86.120x"));

        CHECK(0 == IPvX::parse("18.52.86"));
        CHECK(0 == IPvX::parse("18.52.86a.1"));
        CHECK(0 == IPvX::parse("a18.52.86.1"));
        CHECK(0 == IPvX::parse(".18.52.86.1"));
        CHECK(0 == IPvX::parse("18.52.86.1."));
        CHECK(0 == IPvX::parse("a"));
        CHECK(0 == IPvX::parse(""));
        CHECK(0 == IPvX::parse("18.52.86.120.30"));
        CHECK(0 == IPvX::parse("1800.52.86.120"));
        // TODO CHECK(IPvX::parse("18.52..1") == 0);
    }
}

TEST_CASE("ipv6") {
    SUBCASE("output") {
        {
            std::ostringstream ss;
            ss << IPvX::Formatter(0x1234567890abcdef);
            CHECK(ss.str() == "1234:5678:90ab:cdef::");
        }
        CHECK(to_string(0x1234567890abcdef) == "1234:5678:90ab:cdef::");
        CHECK(to_string(0x1234567890abcde) == "123:4567:890a:bcde::");
        CHECK(to_string(0x1234567890abcd) == "12:3456:7890:abcd::");
        CHECK(to_string(0x1234567890abc) == "1:2345:6789:abc::");
        CHECK(to_string(0x1234567890ab) == "0:1234:5678:90ab::");
        CHECK(to_string(0x1234567890a) == "0:123:4567:890a::");
        CHECK(to_string(0x1234567890) == "0:12:3456:7890::");
        CHECK(to_string(0x123456789) == "0:1:2345:6789::");
        CHECK(to_string(0x1234567890ab0000) == "1234:5678:90ab::");
        CHECK(to_string(0x1234567800000000) == "1234:5678::");
        CHECK(to_string(0x1234000000000000) == "1234::");
        CHECK(to_string(0x1234567890ab0def) == "1234:5678:90ab:def::");
        CHECK(to_string(0x1234567800abcdef) == "1234:5678:ab:cdef::");
        CHECK(to_string(0x1234007890abcdef) == "1234:78:90ab:cdef::");
        CHECK(to_string(0x1234000090abcdef) == "1234:0:90ab:cdef::");
        CHECK(to_string(0x567890abcdef) == "0:5678:90ab:cdef::");
    }

    SUBCASE("parsing") {
        CHECK(0x1234567890abcdef == IPvX::parse("1234:5678:90ab:cdef::"));
        CHECK(0x1234567890abcde == IPvX::parse("123:4567:890a:bcde::"));
        CHECK(0x1234567890abcd == IPvX::parse("12:3456:7890:abcd::"));
        CHECK(0x1234567890abc == IPvX::parse("1:2345:6789:abc::"));
        CHECK(0x1234567890ab == IPvX::parse("0:1234:5678:90ab::"));
        CHECK(0x1234567890a == IPvX::parse("0:123:4567:890a::"));
        CHECK(0x1234567890 == IPvX::parse("0:12:3456:7890::"));
        CHECK(0x123456789 == IPvX::parse("0:1:2345:6789::"));
        CHECK(0x1234567890ab0000 == IPvX::parse("1234:5678:90ab::"));
        CHECK(0x1234567800000000 == IPvX::parse("1234:5678::"));
        CHECK(0x1234000000000000 == IPvX::parse("1234::"));
        CHECK(0x1234567890ab0def == IPvX::parse("1234:5678:90ab:def::"));
        CHECK(0x1234567800abcdef == IPvX::parse("1234:5678:ab:cdef::"));
        CHECK(0x1234007890abcdef == IPvX::parse("1234:78:90ab:cdef::"));
        CHECK(0x1234000090abcdef == IPvX::parse("1234:0:90ab:cdef::"));
        CHECK(0x567890abcdef == IPvX::parse("0:5678:90ab:cdef::"));

        CHECK(0x1234567890abcdef == IPvX::parse("1234:5678:90ab:cdef::x"));
        CHECK(0 == IPvX::parse("x1234:5678:90ab:cdef::"));
        CHECK(0 == IPvX::parse("1234x:5678:90ab:cdef::"));
        CHECK(0 == IPvX::parse("1234:5678x:90ab:cdef::"));
        CHECK(0 == IPvX::parse("1234:5678:90abx:cdef::"));
        CHECK(0 == IPvX::parse("1234:5678:90ab::cdef::"));
        CHECK(0 == IPvX::parse("12345:5678:90ab::cdef::"));
        CHECK(0 == IPvX::parse("1234:5678:90ab:cdef:1234:"));
        // TODO CHECK(0 == IPvX::parse("1234:5678:90ab:cdef:"));
    }
}
