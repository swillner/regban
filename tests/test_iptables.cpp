#define DOCTEST_CONFIG_SUPER_FAST_ASSERTS
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
// make sure doctest comes before including tested classes

#include "test_iptables.h"

TEST_CASE("single") {
    regban::IPTable<Payload> iptable;
    REQUIRE(iptable.size() == 0);

    const auto e1 = create_element(123);
    const auto e2 = create_element(123UL << IPvX::TOTAL_BIT_SIZE_V4);

    {
        const auto& res = iptable.find_or_insert(e1.ip);
        REQUIRE(iptable.size() == 1);
        REQUIRE(!res.first);
        res.second = e1.value;
    }

    {
        const auto& res = iptable.find_or_insert(e2.ip);
        REQUIRE(iptable.size() == 2);
        REQUIRE(!res.first);
        res.second = e2.value;
    }

    SUBCASE("insert again") {
        {
            const auto& res = iptable.find_or_insert(e1.ip);
            REQUIRE(iptable.size() == 2);
            REQUIRE(res.first);
            REQUIRE(res.second == e1.value);
        }
    }

    SUBCASE("find") {
        {
            const auto* res = iptable.find(e1.ip);
            REQUIRE(res != nullptr);
            REQUIRE(*res == e1.value);
        }

        {
            const auto* res = iptable.find(e2.ip);
            REQUIRE(res != nullptr);
            REQUIRE(*res == e2.value);
        }

        {
            const auto* res = iptable.find(0);
            REQUIRE(res == nullptr);
        }
    }

    SUBCASE("lower_bound") {
        {
            const auto e3 = create_element(e1.ip - 2);
            const auto e4 = create_element(e1.ip + 1);
            iptable.find_or_insert(e3.ip).second = e3.value;
            iptable.find_or_insert(e4.ip).second = e4.value;
        }

        {
            const auto res = iptable.lower_bound(e1.ip - 1);
            REQUIRE(res.second != std::end(res.first));
            REQUIRE(res.second->ip == e1.ip - 2);
        }

        {
            const auto res = iptable.lower_bound(e1.ip);
            REQUIRE(res.second != std::end(res.first));
            REQUIRE(res.second->value == e1.value);
        }

        {
            const auto res = iptable.lower_bound(e1.ip + 2);
            REQUIRE(res.second != std::end(res.first));
            REQUIRE(res.second->ip == e1.ip + 1);
        }

        {
            const auto res = iptable.lower_bound(e2.ip + 1);
            REQUIRE(res.second != std::end(res.first));
            REQUIRE(res.second->value == e2.value);
        }

        {
            const auto res = iptable.lower_bound(0);
            REQUIRE(res.second == std::end(res.first));
        }
    }

    SUBCASE("remove") {
        {
            iptable.remove(e1.ip);
            REQUIRE(iptable.size() == 1);
            const auto* res = iptable.find(e1.ip);
            REQUIRE(res == nullptr);
        }

        {
            const auto* res = iptable.find(e2.ip);
            REQUIRE(res != nullptr);
            REQUIRE(*res == e2.value);
        }
    }
}

TEST_CASE("multi") {
    const auto elements = create_element_list(1000);

    regban::IPTable<Payload> iptable;
    for (std::size_t i = 0; i < elements.size(); ++i) {
        const auto& e = elements[i];
        const auto& res = iptable.find_or_insert(e.ip);
        REQUIRE(iptable.size() == i + 1);
        REQUIRE(!res.first);
        res.second = e.value;
    }
    {
        IPvX last = 0;
        for (const auto& j : iptable) {
            const auto cur = j.first;
            const auto cur_bucket = iptable.get_bucket_index(cur);
            const auto last_bucket = iptable.get_bucket_index(last);
            REQUIRE(last_bucket <= cur_bucket);
            if (last_bucket == cur_bucket) {
                REQUIRE(last <= cur);
            }
            last = cur;
        }
    }

    SUBCASE("reserved memory") {
        regban::IPTable<Payload> iptable2(elements.size() / 2);
        for (std::size_t i = 0; i < elements.size(); ++i) {
            const auto& e = elements[i];
            const auto& res = iptable2.find_or_insert(e.ip);
            REQUIRE(iptable2.size() == i + 1);
            REQUIRE(!res.first);
            res.second = e.value;
        }
        {
            IPvX last = 0;
            for (const auto& j : iptable2) {
                const auto cur = j.first;
                const auto cur_bucket = iptable2.get_bucket_index(cur);
                const auto last_bucket = iptable2.get_bucket_index(last);
                REQUIRE(last_bucket <= cur_bucket);
                if (last_bucket == cur_bucket) {
                    REQUIRE(last <= cur);
                }
                last = cur;
            }
        }

        {
            auto it = std::begin(iptable);
            auto it2 = std::begin(iptable2);
            for (std::size_t i = 0; i < elements.size(); ++i) {
                REQUIRE((*it).first == (*it2).first);
                REQUIRE((*it).second == (*it2).second);
                ++it;
                ++it2;
            }
            REQUIRE(it == std::end(iptable));
            REQUIRE(it2 == std::end(iptable2));
        }
    }

    SUBCASE("find") {
        for (std::size_t i = 0; i < elements.size(); ++i) {
            const auto& e = elements[i];
            const auto* res = iptable.find(e.ip);
            REQUIRE(res != nullptr);
            REQUIRE(*res == e.value);
        }

        {
            const auto* res = iptable.find(0);
            REQUIRE(res == nullptr);
        }
    }

    SUBCASE("remove") {
        for (std::size_t i = 0; i < elements.size(); ++i) {
            const auto& e = elements[i];
            {
                const auto* res = iptable.find(e.ip);
                REQUIRE(res != nullptr);
                REQUIRE(*res == e.value);
            }
            iptable.remove(e.ip);
            REQUIRE(iptable.size() == elements.size() - i - 1);
            {
                const auto* res = iptable.find(e.ip);
                REQUIRE(res == nullptr);
            }
        }
    }
}

TEST_CASE("range") {
    regban::IPRangeTable<Payload> iprangetable;
    REQUIRE(iprangetable.size() == 0);

    const auto e1 = create_element(IPvX::parse("192.168.1.64"));
    const auto e2 = create_element(IPvX::parse("fd00:11::64"));

    {
        const auto& res = iprangetable.find_or_insert(e1.ip, 24);
        REQUIRE(iprangetable.size() == 1);
        REQUIRE(!res.first);
        res.second = e1.value;
    }

    {
        const auto& res = iprangetable.find_or_insert(e2.ip, 64);
        REQUIRE(iprangetable.size() == 2);
        REQUIRE(!res.first);
        res.second = e2.value;
    }

    SUBCASE("insert again") {
        {
            const auto& res = iprangetable.find_or_insert(e1.ip, 32);
            REQUIRE(iprangetable.size() == 2);
            REQUIRE(res.first);
            REQUIRE(res.second == e1.value);
        }
    }

    SUBCASE("find") {
        {
            const auto res = iprangetable.find_range_for(e1.ip);
            const auto& res_ip = res.first.first;
            const auto& cidr = res.first.second;
            const auto* value = res.second;
            REQUIRE(res_ip == e1.ip);
            REQUIRE(cidr == 24);
            REQUIRE(*value == e1.value);
        }

        {
            const auto ip = IPvX::parse("192.168.1.128");
            const auto res = iprangetable.find_range_for(ip);
            const auto& res_ip = res.first.first;
            const auto& cidr = res.first.second;
            const auto* value = res.second;
            REQUIRE(res_ip == e1.ip);
            REQUIRE(cidr == 24);
            REQUIRE(*value == e1.value);
        }

        {
            const auto ip = IPvX::parse("192.168.2.3");
            const auto res = iprangetable.find_range_for(ip);
            const auto& res_ip = res.first.first;
            const auto& cidr = res.first.second;
            const auto* value = res.second;
            REQUIRE(res_ip == ip);
            REQUIRE(cidr == 0);
            REQUIRE(value == nullptr);
        }

        {
            const auto res = iprangetable.find_range_for(e2.ip);
            const auto& res_ip = res.first.first;
            const auto& cidr = res.first.second;
            const auto* value = res.second;
            REQUIRE(res_ip == e2.ip);
            REQUIRE(cidr == 64);
            REQUIRE(*value == e2.value);
        }

        {
            const auto ip = IPvX::parse("fd00:11:0:0:1::");
            const auto res = iprangetable.find_range_for(ip);
            const auto& res_ip = res.first.first;
            const auto& cidr = res.first.second;
            const auto* value = res.second;
            REQUIRE(res_ip == e2.ip);
            REQUIRE(cidr == 64);
            REQUIRE(*value == e2.value);
        }

        {
            const auto ip = IPvX::parse("fd00:12::");
            const auto res = iprangetable.find_range_for(ip);
            const auto& res_ip = res.first.first;
            const auto& cidr = res.first.second;
            const auto* value = res.second;
            REQUIRE(res_ip == ip);
            REQUIRE(cidr == 0);
            REQUIRE(value == nullptr);
        }
    }
}
