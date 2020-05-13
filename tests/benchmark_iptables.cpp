#define ANKERL_NANOBENCH_IMPLEMENT
#include "nanobench.h"
namespace nanobench = ankerl::nanobench;

#include "test_iptables.h"

int main() {
    constexpr auto N = 10000;
    const auto elements = create_element_list(2 * N);

    {
        nanobench::Config cfg;
        cfg.title("insert").unit(std::to_string(N) + "ips").relative(true);

        cfg.run("std::map", [&] {
            std::map<IPvX, Payload> std_map;
            for (auto i = 0; i < N; ++i) {
                const auto& e = elements[i];
                std_map.emplace(e.ip, e.value);
            }
        });

        cfg.run("regban::IPTable", [&] {
            regban::IPTable<Payload> iptable;
            for (auto i = 0; i < N; ++i) {
                const auto& e = elements[i];
                iptable.find_or_insert(e.ip).second = e.value;
            }
        });

        cfg.run("regban::IPTable (prereserved)", [&] {
            regban::IPTable<Payload> iptable2(N);
            for (auto i = 0; i < N; ++i) {
                const auto& e = elements[i];
                iptable2.find_or_insert(e.ip).second = e.value;
            }
        });
    }

    {
        std::map<IPvX, Payload> std_map;
        for (const auto e : elements) {
            std_map.emplace(std::make_pair(e.ip, e.value));
        }

        regban::IPTable<Payload> iptable;
        for (const auto e : elements) {
            iptable.find_or_insert(e.ip).second = e.value;
        }

        {
            nanobench::Config cfg;
            cfg.title("find (hit)").unit(std::to_string(N) + "ips").relative(true);

            cfg.run("std::map", [&] {
                for (auto i = 0; i < N; ++i) {
                    const auto& res = std_map.find(elements[i].ip);
                }
            });

            cfg.run("regban::IPTable", [&] {
                for (auto i = 0; i < N; ++i) {
                    const auto* res = iptable.find(elements[i].ip);
                }
            });
        }

        {
            nanobench::Config cfg;
            cfg.title("find (miss)").unit(std::to_string(N) + "ips").relative(true).minEpochIterations(100);

            cfg.run("std::map", [&] {
                for (auto i = N; i < 2 * N; ++i) {
                    const auto& res = std_map.find(elements[i].ip);
                }
            });

            cfg.run("regban::IPTable", [&] {
                for (auto i = N; i < 2 * N; ++i) {
                    const auto* res = iptable.find(elements[i].ip);
                }
            });
        }
    }

    return 0;
}
