#pragma once
#include "core/models/PacketModel.h"
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <memory>
#include <cstdint>

/// Generates realistic synthetic packets when real capture is unavailable.
class SimulatedPacketSource
{
public:
    explicit SimulatedPacketSource(int packets_per_second = 40);
    ~SimulatedPacketSource();

    void start();
    void stop();
    bool isRunning() const { return running_.load(); }

    void setPacketCallback(std::function<void(std::shared_ptr<const UnifiedPacket>)> cb);

private:
    std::function<void(std::shared_ptr<const UnifiedPacket>)> callback_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    int pps_;
    uint64_t next_id_{1};
    uint32_t next_flow_id_{1};

    void generateLoop();

    // Packet factory helpers – each returns a fully populated UnifiedPacket.
    UnifiedPacket makeTCPSyn(const std::string &src, const std::string &dst,
                             uint16_t sport, uint16_t dport, uint32_t flow_id);
    UnifiedPacket makeTCPSynAck(const std::string &src, const std::string &dst,
                                uint16_t sport, uint16_t dport, uint32_t flow_id);
    UnifiedPacket makeTCPAck(const std::string &src, const std::string &dst,
                             uint16_t sport, uint16_t dport,
                             uint32_t seq, uint32_t flow_id);
    UnifiedPacket makeHTTPGet(const std::string &src, const std::string &dst,
                              uint32_t flow_id);
    UnifiedPacket makeHTTPResponse(const std::string &src, const std::string &dst,
                                   uint32_t flow_id);
    UnifiedPacket makeDNSQuery(const std::string &src, const std::string &dst,
                               const std::string &name, uint32_t flow_id);
    UnifiedPacket makeDNSResponse(const std::string &src, const std::string &dst,
                                  const std::string &name, const std::string &answer,
                                  uint32_t flow_id);
    UnifiedPacket makeICMPEcho(const std::string &src, const std::string &dst,
                               uint32_t flow_id);
    UnifiedPacket makeTCPRst(const std::string &src, const std::string &dst,
                             uint32_t flow_id);

    /// Fill raw_data with syntactically plausible header bytes and update
    /// all offset / length fields and packet_size.
    void fillRawBytes(UnifiedPacket &pkt);

    /// Deliver a packet: invoke callback AND publish to EventBus.
    void deliver(UnifiedPacket pkt);
};