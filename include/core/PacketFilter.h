#pragma once
#include "core/models/PacketModel.h"
#include <string>
#include <vector>

enum class FilterField
{
    IP_SRC,
    IP_DST,
    TCP_PORT,
    UDP_PORT,
    PROTOCOL
};
enum class FilterOp
{
    EQ,
    NEQ,
    GT,
    LT
};

struct FilterRule
{
    FilterField field;
    FilterOp op;
    std::string value;
};

/// Simple BPF-style packet filter.
/// Supported syntax (space-separated tokens):
///   ip.src == 1.2.3.4
///   ip.dst != 5.6.7.8
///   tcp.port == 80
///   udp.port == 53
///   protocol == TCP|UDP|ICMP|DNS|HTTP
/// Multiple rules are AND-ed together.
class PacketFilter
{
public:
    /// Parse the filter string.  Returns true on success.
    bool parse(const std::string &filter_string);

    /// Returns true if pkt matches all current rules.
    bool matches(const UnifiedPacket &pkt) const;

    void clear();
    std::string getError() const { return parse_error_; }

private:
    bool matchRule(const UnifiedPacket &pkt, const FilterRule &rule) const;

    std::vector<FilterRule> rules_;
    std::string parse_error_;
};