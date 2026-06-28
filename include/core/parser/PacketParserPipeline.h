#pragma once
#include "core/models/PacketModel.h"
#include <cstdint>
#include <cstddef>
#include <memory>

/// Stateless L2-L7 parser.  All methods are static.
class PacketParserPipeline
{
public:
    /// Parse raw captured bytes into a fully populated UnifiedPacket.
    /// BUG1-FIX: returns shared_ptr so the single allocation is shared
    /// across all consumers — eliminates the 7-9 deep copies per packet.
    static std::shared_ptr<const UnifiedPacket> parse(uint64_t id,
                                                      const uint8_t *data,
                                                      size_t len,
                                                      double timestamp);

private:
    static void parseEthernet(UnifiedPacket &pkt);
    static void parseIPv4(UnifiedPacket &pkt);
    static void parseIPv6(UnifiedPacket &pkt);
    static void parseTCP(UnifiedPacket &pkt);
    static void parseUDP(UnifiedPacket &pkt);
    static void parseICMP(UnifiedPacket &pkt);
    static void parseHTTP(UnifiedPacket &pkt);
    static void parseTLS(UnifiedPacket &pkt);
    static void parseDNS(UnifiedPacket &pkt);
};
