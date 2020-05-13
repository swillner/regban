#ifndef IPTABLE_H
#define IPTABLE_H

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "IPvX.h"

namespace regban {

template<typename T>
class IPTable;

template<typename T>
class IPTable_iterator {
    friend class IPTable<T>;

  protected:
    std::size_t bucket_index;
    std::size_t pos_in_bucket;
    IPTable<T>& ip_table;
    IPTable_iterator(IPTable<T>& ip_table_p, std::size_t bucket_index_p, std::size_t pos_in_bucket_p)
        : ip_table(ip_table_p), bucket_index(bucket_index_p), pos_in_bucket(pos_in_bucket_p) {}

  public:
    void operator++() {
        if (bucket_index < ip_table.buckets.size()) {
            ++pos_in_bucket;
            if (pos_in_bucket >= ip_table.buckets[bucket_index].size()) {
                pos_in_bucket = 0;
                ++bucket_index;
                for (; bucket_index < ip_table.buckets.size(); ++bucket_index) {
                    if (ip_table.buckets[bucket_index].size() > 0) {
                        break;
                    }
                }
            }
        }
    }
    const std::pair<IPvX, T&> operator*() const {
        const auto& cur = ip_table.buckets[bucket_index][pos_in_bucket];
        return {cur.ip, cur.value};
    }
    std::pair<IPvX, T&> operator*() {
        auto& cur = ip_table.buckets[bucket_index][pos_in_bucket];
        return {cur.ip, cur.value};
    }
    bool operator==(const IPTable_iterator& rhs) const { return bucket_index == rhs.bucket_index && pos_in_bucket == rhs.pos_in_bucket; }
    bool operator!=(const IPTable_iterator& rhs) const { return bucket_index != rhs.bucket_index || pos_in_bucket != rhs.pos_in_bucket; }
};

template<typename T>
class IPTable {
    friend class IPTable_iterator<T>;

  public:
    static constexpr char INDEX_WORD_BIT_SIZE_V4 = 8;
    static constexpr char INDEX_WORD_BIT_SIZE_V6 = 12;
    static constexpr char SKIP_BITS_V6 = 6;

    struct Element {
        IPvX ip = 0;
        T value;
    };

    using iterator = IPTable_iterator<T>;

    iterator begin() {
        for (std::size_t i = 0; i < buckets.size(); ++i) {
            if (buckets[i].size() > 0) {
                return {*this, i, 0};
            }
        }
        return {*this, buckets.size(), 0};
    }
    iterator end() { return {*this, buckets.size(), 0}; }

#ifdef DOCTEST_LIBRARY_INCLUDED
  public:
#else
  protected:
#endif
    using Bucket = std::vector<Element>;
    std::array<Bucket, (1 << INDEX_WORD_BIT_SIZE_V4) + (1 << INDEX_WORD_BIT_SIZE_V6)> buckets;
    std::size_t size_m = 0;

    static constexpr unsigned int get_bucket_index(IPvX ip) {
        if (ip.is_ipv6()) {
            return ((ip >> (IPvX::TOTAL_BIT_SIZE_V6 - INDEX_WORD_BIT_SIZE_V6 - SKIP_BITS_V6)) & ((1 << INDEX_WORD_BIT_SIZE_V6) - 1))
                   + (1 << INDEX_WORD_BIT_SIZE_V4);
        } else {
            return (ip >> (IPvX::TOTAL_BIT_SIZE_V4 - INDEX_WORD_BIT_SIZE_V4));
        }
    }

    // get largest element in bucket smaller than ip
    std::pair<Bucket&, typename Bucket::iterator> lower_bound(IPvX ip) {
        auto& bucket = buckets[get_bucket_index(ip)];
        std::size_t begin = 0;
        std::size_t end = bucket.size();

        if (begin == end) {
            return {bucket, std::end(bucket)};
        }

        if (bucket[begin].ip > ip) {
            return {bucket, std::end(bucket)};
        }

        while (begin + 1 < end) {
            const auto res = (begin + end) / 2;
            if (bucket[res].ip <= ip) {
                begin = res;
            } else {
                end = res;
            }
        }

        return {bucket, std::begin(bucket) + begin};
    }

  public:
    IPTable() { clear(); }
    explicit IPTable(std::size_t size_p) { clear_and_reserve(size_p); }

    std::size_t size() const { return size_m; }

    void clear_and_reserve(std::size_t size_p) {
        size_m = 0;
        const auto bucket_size = (size_p + buckets.size() - 1) / buckets.size();
        for (int i = 0; i < buckets.size(); ++i) {
            buckets[i].clear();
            buckets[i].reserve(bucket_size);
        }
    }

    void clear() {
        size_m = 0;
        for (std::size_t i = 0; i < buckets.size(); ++i) {
            buckets[i].clear();
        }
    }

    T* find(IPvX ip) {
        const auto res = lower_bound(ip);
        if (res.second != std::end(res.first) && res.second->ip == ip) {
            return &res.second->value;
        }
        return nullptr;
    }

    std::pair<bool, T&> find_or_insert(IPvX ip) {
        auto res = lower_bound(ip);
        if (res.second != std::end(res.first)) {
            if (res.second->ip == ip) {
                return {true, res.second->value};
            }
            ++size_m;
            return {false, res.first.insert(res.second + 1, {ip, T{}})->value};
        }
        ++size_m;
        return {false, res.first.insert(std::begin(res.first), {ip, T{}})->value};
    }

    void remove(IPvX ip) {
        auto res = lower_bound(ip);
        if (res.second != std::end(res.first) && res.second->ip == ip) {
            res.first.erase(res.second);
            --size_m;
        }
    }
};

template<typename T>
struct IPRangeValue {
    unsigned char cidr_suffix;
    T value;
};

template<typename T>
class IPRangeTable : public IPTable<IPRangeValue<T>> {
  public:
    using IPTable<IPRangeValue<T>>::find_or_insert;

    std::pair<bool, T&> find_or_insert(IPvX ip, unsigned char cidr_suffix) {
        auto res = find_or_insert(ip);
        if (!res.first) {
            // was actually inserted
            if ((ip.is_ipv6() && cidr_suffix < IPTable<IPRangeValue<T>>::SKIP_BITS_V6 + IPTable<IPRangeValue<T>>::INDEX_WORD_BIT_SIZE_V6)
                || (!ip.is_ipv6() && cidr_suffix < IPTable<IPRangeValue<T>>::INDEX_WORD_BIT_SIZE_V4)) {
                std::ostringstream ss;
                ss << ip;
                throw std::runtime_error("CIDR suffix " + std::to_string(static_cast<int>(cidr_suffix)) + " for " + ss.str() + " is too small for indexing");
            }
            res.second.cidr_suffix = cidr_suffix;
        }
        return {res.first, res.second.value};
    }

    std::pair<std::pair<IPvX, char>, T*> find_range_for(IPvX ip) {
        auto res = this->lower_bound(ip);
        if (res.second != std::end(res.first)) {
            char shift;
            if (ip.is_ipv6()) {
                shift = IPvX::TOTAL_BIT_SIZE_V6 - res.second->value.cidr_suffix;
            } else {
                shift = IPvX::TOTAL_BIT_SIZE_V4 - res.second->value.cidr_suffix;
            }
            if ((ip >> shift) == (res.second->ip >> shift)) {
                return {{res.second->ip, res.second->value.cidr_suffix}, &res.second->value.value};
            }
        }
        return {{ip, 0}, nullptr};
    }
};

}  // namespace regban

template<typename T>
struct std::iterator_traits<typename regban::IPTable_iterator<T>> {
    using value_type = std::pair<regban::IPvX, T>;
    using difference_type = void;
    using pointer = void;
    using reference = std::pair<regban::IPvX, T&>;
    using iterator_category = std::forward_iterator_tag;
};

#endif
