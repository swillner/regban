#ifndef TEST_IPTABLES_H
#define TEST_IPTABLES_H

#include <limits>
#include <random>
#include <vector>

#include "IPTable.h"
#include "IPvX.h"
using regban::IPvX;

using Payload = int;

regban::IPTable<Payload>::Element create_element(IPvX ip) { return {ip, static_cast<int>(ip >> 5)}; }

static std::vector<regban::IPTable<Payload>::Element> create_element_list(std::size_t N) {
    std::vector<regban::IPTable<Payload>::Element> res(N);
    std::mt19937 gen(0);
    std::uniform_int_distribution<int> dist_bool(0, 1);
    std::uniform_int_distribution<IPvX::IPv4> dist_v4(0, std::numeric_limits<IPvX::IPv4>::max());
    std::uniform_int_distribution<IPvX::Internal> dist_v6(0, std::numeric_limits<IPvX::Internal>::max());

    for (int i = 0; i < N; ++i) {
        IPvX ip;
        if (dist_bool(gen) == 0) {
            ip = dist_v4(gen);
        } else {
            do {
                ip = dist_v6(gen);
            } while (!ip.is_ipv6());
        }
        res[i] = create_element(ip);
    }

    return res;
}

#endif
