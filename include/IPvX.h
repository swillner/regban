#ifndef IPVX_H
#define IPVX_H

#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

namespace regban {

class IPvX {
  public:
    using Internal = std::uint64_t;
    using IPv4 = std::uint32_t;
    static constexpr char TOTAL_BIT_SIZE_V4 = 32;
    static constexpr char TOTAL_BIT_SIZE_V6 = 64;
    static constexpr Internal IPv6_MASK = ((1UL << TOTAL_BIT_SIZE_V4) - 1) << TOTAL_BIT_SIZE_V4;
    class Formatter;

  private:
    Internal v;

  public:
    constexpr IPvX() : v(0) {}
    constexpr IPvX(Internal value) : v(value) {}
    constexpr bool is_ipv6() const { return v & IPv6_MASK; }
    constexpr operator Internal() const { return v; }

    std::array<unsigned char, 4> byte_representation_v4() const {
        return {static_cast<unsigned char>(v >> 24), static_cast<unsigned char>(v >> 16), static_cast<unsigned char>(v >> 8), static_cast<unsigned char>(v)};
    }

    std::array<unsigned char, 16> byte_representation_v6() const {
        return {static_cast<unsigned char>(v >> 56),
                static_cast<unsigned char>(v >> 48),
                static_cast<unsigned char>(v >> 40),
                static_cast<unsigned char>(v >> 32),
                static_cast<unsigned char>(v >> 24),
                static_cast<unsigned char>(v >> 16),
                static_cast<unsigned char>(v >> 8),
                static_cast<unsigned char>(v),
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0};
    }

    template<typename Char>
    friend std::basic_ostream<Char>& operator<<(std::basic_ostream<Char>& os, const IPvX& ip) {
        if (ip.is_ipv6()) {
            os << std::hex;
            os << ((ip.v >> 48) & 0xffff);
            if ((ip.v & ((1UL << 48) - 1)) != 0) {
                os << ':' << ((ip.v >> 32) & 0xffff);
                if ((ip.v & ((1UL << 32) - 1)) != 0) {
                    os << ':' << ((ip.v >> 16) & 0xffff);
                    if ((ip.v & ((1UL << 16) - 1)) != 0) {
                        os << ':' << (ip.v & 0xffff);
                    }
                }
            }
            os << ':' << ':' << std::dec;
        } else {
            os << ((ip.v >> 24) & 0xff) << '.';
            os << ((ip.v >> 16) & 0xff) << '.';
            os << ((ip.v >> 8) & 0xff) << '.';
            os << (ip.v & 0xff);
        }
        return os;
    }

    static IPvX parse(const char* c) {
        Internal res = 0;
        const auto* pos = c;
        char* end;
        auto last = *pos;
        if (std::strchr(pos, ':') != nullptr) {
            // should be an IPv6
            int i;
            for (i = 0; i < 4; ++i) {  // only parse first half
                const auto v = std::strtoul(pos, &end, 16);
                if (v > 0xffff) {
                    return 0;
                }
                if (last == ':') {
                    break;
                }
                if (*end != ':') {
                    return 0;
                }
                res = (res << 16) | v;
                last = *pos;
                pos = end + 1;
            }
            if (*pos != ':' && *pos != '\0') {
                return 0;
            }
            return res << ((4 - i) * 16);
        }
        // should be an IPv4
        for (int i = 0; i < 4; ++i) {
            const auto v = std::strtoul(pos, &end, 10);
            if (v > 255 || (i < 3 && *end != '.') || (i == 3 && *end == '.')) {
                return 0;
            }
            res = (res << 8) | v;
            pos = end + 1;
        }
        return res;
    }
};

class IPvX::Formatter {
  private:
    IPvX ip;

  public:
    Formatter(IPvX ip_p) : ip(ip_p) {}
    template<typename Char>
    friend std::basic_ostream<Char>& operator<<(std::basic_ostream<Char>& os, const IPvX::Formatter& f) {
        return os << f.ip;
    }
};

}  // namespace regban

#endif
