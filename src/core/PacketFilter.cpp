#include "core/PacketFilter.h"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace {
std::string upper(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return s;
}
}

bool PacketFilter::parse(const std::string& filter_string)
{
    rules_.clear();
    parse_error_.clear();
    if (filter_string.empty()) {
        return true;
    }

    std::vector<std::string> tokens;
    std::istringstream ss(filter_string);
    for (std::string tok; ss >> tok;) {
        if (upper(tok) != "AND") {
            tokens.push_back(tok);
        }
    }

    if (tokens.size() % 3 != 0) {
        parse_error_ = "Filter must use field operator value triplets";
        return false;
    }

    for (size_t i = 0; i < tokens.size(); i += 3) {
        const std::string& field_str = tokens[i];
        const std::string& op_str = tokens[i + 1];
        const std::string& value_str = tokens[i + 2];
        FilterRule rule;

        if (field_str == "ip.src") {
            rule.field = FilterField::IP_SRC;
        } else if (field_str == "ip.dst") {
            rule.field = FilterField::IP_DST;
        } else if (field_str == "tcp.port") {
            rule.field = FilterField::TCP_PORT;
        } else if (field_str == "udp.port") {
            rule.field = FilterField::UDP_PORT;
        } else if (field_str == "protocol") {
            rule.field = FilterField::PROTOCOL;
        } else {
            parse_error_ = "Unknown field: " + field_str;
            rules_.clear();
            return false;
        }

        if (op_str == "==") {
            rule.op = FilterOp::EQ;
        } else if (op_str == "!=") {
            rule.op = FilterOp::NEQ;
        } else if (op_str == ">") {
            rule.op = FilterOp::GT;
        } else if (op_str == "<") {
            rule.op = FilterOp::LT;
        } else {
            parse_error_ = "Unknown operator: " + op_str;
            rules_.clear();
            return false;
        }

        rule.value = value_str;
        rules_.push_back(rule);
    }
    return true;
}

bool PacketFilter::matchRule(const UnifiedPacket& pkt, const FilterRule& r) const
{
    auto cmpStr = [&](const std::string& a, const std::string& b) -> bool {
        switch (r.op) {
        case FilterOp::EQ:
            return a == b;
        case FilterOp::NEQ:
            return a != b;
        default:
            return false;
        }
    };

    auto cmpPort = [&](uint16_t port) -> bool {
        unsigned long parsed = 0;
        try {
            parsed = std::stoul(r.value);
        } catch (...) {
            return false;
        }
        if (parsed > 65535UL) {
            return false;
        }
        const auto v = static_cast<uint16_t>(parsed);
        switch (r.op) {
        case FilterOp::EQ:
            return port == v;
        case FilterOp::NEQ:
            return port != v;
        case FilterOp::GT:
            return port > v;
        case FilterOp::LT:
            return port < v;
        }
        return false;
    };

    switch (r.field) {
    case FilterField::IP_SRC:
        return cmpStr(pkt.src_ip, r.value);
    case FilterField::IP_DST:
        return cmpStr(pkt.dst_ip, r.value);
    case FilterField::TCP_PORT:
        return pkt.has_tcp && (cmpPort(pkt.src_port) || cmpPort(pkt.dst_port));
    case FilterField::UDP_PORT:
        return pkt.has_udp && (cmpPort(pkt.src_port) || cmpPort(pkt.dst_port));
    case FilterField::PROTOCOL:
        return cmpStr(upper(protocolToString(pkt.protocol)), upper(r.value));
    }
    return false;
}

bool PacketFilter::matches(const UnifiedPacket& pkt) const
{
    return std::all_of(rules_.begin(), rules_.end(), [&](const FilterRule& r) {
        return matchRule(pkt, r);
    });
}

void PacketFilter::clear()
{
    rules_.clear();
    parse_error_.clear();
}
