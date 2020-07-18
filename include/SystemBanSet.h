#ifndef SYSTEMBANSET_H
#define SYSTEMBANSET_H

#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <stdexcept>

#include "IPvX.h"
#include "spdlog/spdlog.h"

// include last
#include "spdlog/fmt/ostr.h"

namespace regban {

class SystemBanSet {
  public:
    static constexpr uint32_t KEY_TYPE_IPv4 = 7;  // see nftables/include/datatype.h
    static constexpr uint32_t KEY_TYPE_IPv6 = 8;  // see nftables/include/datatype.h

  private:
    uint32_t table_type;
    mnl_socket* nl = nullptr;
    nftnl_set* current_ipv4_set = nullptr;
    nftnl_set* current_ipv6_set = nullptr;
    std::shared_ptr<spdlog::logger> logger;
    std::string set_v4_name;
    std::string set_v6_name;
    std::string table_name;
    std::string table_type_name;
    uint32_t portid;

    void check_set(const std::string& set_name, uint32_t key_type) {
        std::vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
        uint32_t seq = std::time(nullptr);

        auto* t = nftnl_set_alloc();
        if (t == nullptr) {
            throw std::bad_alloc();
        }
        auto* nlh = nftnl_set_nlmsg_build_hdr(&buf[0], NFT_MSG_GETSET, table_type, NLM_F_DUMP | NLM_F_ACK, seq);
        nftnl_set_set_str(t, NFTNL_SET_TABLE, table_name.c_str());
        nftnl_set_set_u32(t, NFTNL_SET_FAMILY, table_type);
        nftnl_set_nlmsg_build_payload(nlh, t);
        nftnl_set_free(t);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            throw std::runtime_error(std::string("Could not send to mnl socket: ") + std::strerror(errno));
        }

        struct CheckData {
            const std::string& name;
            uint32_t key_type;
            std::shared_ptr<spdlog::logger> logger;
            bool found;
        };
        CheckData data = {set_name, key_type, logger, false};

        auto ret = mnl_socket_recvfrom(nl, &buf[0], buf.size());
        while (ret > 0) {
            ret = mnl_cb_run(
                &buf[0], ret, seq, portid,
                [](const nlmsghdr* nlh, void* data) {
                    auto* d = static_cast<CheckData*>(data);
                    auto* t = nftnl_set_alloc();
                    if (t == nullptr) {
                        throw std::bad_alloc();
                    }

                    if (nftnl_set_nlmsg_parse(nlh, t) < 0) {
                        d->logger->error("nft message parsing failed");
                        nftnl_set_free(t);
                        return MNL_CB_OK;
                    }

                    const auto* name = nftnl_set_get_str(t, NFTNL_SET_NAME);
                    d->logger->debug("Found nftable {}", name);
                    if (d->name == name) {
                        d->found = true;
                        if ((nftnl_set_get_u32(t, NFTNL_SET_FLAGS) & NFT_SET_TIMEOUT) == 0) {
                            nftnl_set_free(t);
                            throw std::runtime_error("nftable set " + d->name + " does not support timeouts");
                        }
                        if (d->key_type == KEY_TYPE_IPv6 && (nftnl_set_get_u32(t, NFTNL_SET_FLAGS) & NFT_SET_INTERVAL) == 0) {
                            nftnl_set_free(t);
                            throw std::runtime_error("nftable set " + d->name + " does not support intervals");
                        }
                        if (nftnl_set_get_u32(t, NFTNL_SET_KEY_TYPE) != d->key_type) {
                            nftnl_set_free(t);
                            throw std::runtime_error("nftable set " + d->name + " is of wrong type");
                        }
                    }

                    nftnl_set_free(t);
                    return MNL_CB_OK;
                },
                &data);
            if (ret <= 0) {
                break;
            }
            ret = mnl_socket_recvfrom(nl, &buf[0], buf.size());
        }
        if (ret == -1) {
            if (errno == ENOENT) {
                throw std::runtime_error("nftable " + table_name + " of " + table_type_name + " type not found");
            }
            throw std::runtime_error(std::string("Error received from mnl socket: ") + std::strerror(errno));
        }
        if (!data.found) {
            throw std::runtime_error("nftable set " + set_name + " not found");
        }
    }

  public:
    SystemBanSet() { logger = spdlog::default_logger()->clone("SystemBanSet"); }

    void initialize(std::string table_type_name_p, std::string table_name_p, std::string set_v4_name_p, std::string set_v6_name_p) {
        logger->debug("Initializing");
        table_name = std::move(table_name_p);
        table_type_name = std::move(table_type_name_p);
        if (table_type_name == "inet") {
            table_type = NFPROTO_INET;
        } else if (table_type_name == "ip") {
            table_type = NFPROTO_IPV4;
        } else if (table_type_name == "ip6") {
            table_type = NFPROTO_IPV6;
        } else if (table_type_name == "bridge") {
            table_type = NFPROTO_BRIDGE;
        } else if (table_type_name == "arp") {
            table_type = NFPROTO_ARP;
        } else if (table_type_name == "unspec") {
            table_type = NFPROTO_UNSPEC;
        } else {
            throw std::runtime_error("Invalid table type '" + table_type_name + "', use inet, ip, ip6, bridge, arp, or unspec");
        }

        set_v4_name = std::move(set_v4_name_p);
        set_v6_name = std::move(set_v6_name_p);

        logger->debug("Opening MNL socket");
        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == nullptr) {
            throw std::runtime_error(std::string("Could not open mnl socket: ") + std::strerror(errno));
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
            throw std::runtime_error(std::string("Could not bind to mnl socket: ") + std::strerror(errno));
        }
        portid = mnl_socket_get_portid(nl);

        logger->debug("Checking set {} of ipv4 type", set_v4_name);
        check_set(set_v4_name, KEY_TYPE_IPv4);
        logger->debug("Checking set {} of ipv6 type", set_v6_name);
        check_set(set_v6_name, KEY_TYPE_IPv6);
    }

    ~SystemBanSet() {
        if (nl != nullptr) {
            mnl_socket_close(nl);
        }
        if (current_ipv6_set != nullptr) {
            nftnl_set_free(current_ipv6_set);
        }
        if (current_ipv4_set != nullptr) {
            nftnl_set_free(current_ipv4_set);
        }
    }

    void add_ip(IPvX ip, unsigned int timeout) {  // timeout in seconds
        auto* e = nftnl_set_elem_alloc();
        if (e == nullptr) {
            throw std::bad_alloc();
        }
        nftnl_set* current_set;
        if (ip.is_ipv6()) {
            logger->debug("Adding ipv6 {}", IPvX::Formatter(ip));
            const auto begin = ip.byte_representation_v6();
            const auto end = IPvX(ip + 1).byte_representation_v6();
            nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &begin[0], begin.size());
            nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY_END, &end[0], end.size());
            current_set = current_ipv6_set;
        } else {
            logger->debug("Adding ipv4 {}", IPvX::Formatter(ip));
            const auto d = ip.byte_representation_v4();
            nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, &d[0], d.size());
            current_set = current_ipv4_set;
        }
        if (timeout > 0) {
            logger->debug("Setting timeout to {}", timeout * 1000);
            nftnl_set_elem_set_u64(e, NFTNL_SET_ELEM_TIMEOUT, timeout * 1000);
        }
        if (current_set == nullptr) {
            logger->debug("Allocating new set data");
            current_set = nftnl_set_alloc();
            if (current_set == nullptr) {
                throw std::bad_alloc();
            }
            nftnl_set_set_str(current_set, NFTNL_SET_TABLE, table_name.c_str());
            nftnl_set_set_u32(current_set, NFTNL_SET_FAMILY, table_type);
            if (ip.is_ipv6()) {
                nftnl_set_set_u32(current_set, NFTNL_SET_KEY_LEN, 16 * 8);
                nftnl_set_set_u32(current_set, NFTNL_SET_KEY_TYPE, KEY_TYPE_IPv6);
                nftnl_set_set_str(current_set, NFTNL_SET_NAME, set_v6_name.c_str());
                current_ipv6_set = current_set;
            } else {
                nftnl_set_set_u32(current_set, NFTNL_SET_KEY_LEN, 4 * 8);
                nftnl_set_set_u32(current_set, NFTNL_SET_KEY_TYPE, KEY_TYPE_IPv4);
                nftnl_set_set_str(current_set, NFTNL_SET_NAME, set_v4_name.c_str());
                current_ipv4_set = current_set;
            }
        }
        nftnl_set_elem_add(current_set, e);
    }

    void commit_batch() {
        if (current_ipv4_set == nullptr && current_ipv6_set == nullptr) {
            logger->debug("Empty commit, ignoring");
            return;
        }

        std::vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
        auto* batch = mnl_nlmsg_batch_start(&buf[0], buf.size());

        uint32_t seq = std::time(nullptr);
        nftnl_batch_begin(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
        mnl_nlmsg_batch_next(batch);

        if (current_ipv6_set != nullptr) {
            logger->debug("Committing ipv6 data");
            auto* nlh = nftnl_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWSETELEM, table_type,
                                              NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, seq++);
            nftnl_set_elems_nlmsg_build_payload(nlh, current_ipv6_set);
            nftnl_set_free(current_ipv6_set);
            current_ipv6_set = nullptr;
            mnl_nlmsg_batch_next(batch);
        }

        if (current_ipv4_set != nullptr) {
            logger->debug("Committing ipv4 data");
            auto* nlh = nftnl_nlmsg_build_hdr(static_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWSETELEM, table_type,
                                              NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK, seq++);
            nftnl_set_elems_nlmsg_build_payload(nlh, current_ipv4_set);
            nftnl_set_free(current_ipv4_set);
            current_ipv4_set = nullptr;
            mnl_nlmsg_batch_next(batch);
        }

        nftnl_batch_end(static_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
        mnl_nlmsg_batch_next(batch);

        if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
            throw std::runtime_error(std::string("Could not send to mnl socket: ") + std::strerror(errno));
        }

        mnl_nlmsg_batch_stop(batch);

        auto ret = mnl_socket_recvfrom(nl, &buf[0], buf.size());
        while (ret > 0) {
            ret = mnl_cb_run(&buf[0], ret, 0, portid, nullptr, nullptr);
            if (ret <= 0) {
                break;
            }
            ret = mnl_socket_recvfrom(nl, &buf[0], buf.size());
        }
        if (ret == -1) {
            switch (errno) {
                case EEXIST:
                    logger->error("ip already in table");
                    break;
                case ENOENT:
                    throw std::runtime_error("nftable or set not found");
                default:
                    throw std::runtime_error(std::string("Error received from mnl socket: ") + std::strerror(errno));
            }
        }
    }
};
}  // namespace regban

#endif
