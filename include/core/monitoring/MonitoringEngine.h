#pragma once
#include "core/models/PacketModel.h"
#include "core/models/FlowModel.h"
#include "core/models/MetricsModel.h"
#include <thread>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <vector>
#include <chrono>

class MonitoringEngine
{
public:
    MonitoringEngine()  = default;
    ~MonitoringEngine() { stop(); }

    void start();
    void stop();

    void ingestPacket(const UnifiedPacket &pkt);

    NetworkMetrics    getMetricsCopy()  const;
    std::vector<Flow> getActiveFlows()  const;

private:
    void monitorLoop();
    void computeMetrics();
    void detectAnomalies();

    void updateFlow(const UnifiedPacket &pkt);
    void updateTCPState(Flow &flow, const UnifiedPacket &pkt);

    NetworkMetrics metrics_;
    std::unordered_map<uint32_t, Flow> flows_;
    mutable std::mutex flows_mutex_;

    std::thread monitor_thread_;
    std::atomic<bool> running_{false};

    uint64_t last_total_packets_{0};
    uint64_t last_total_bytes_{0};
    std::chrono::steady_clock::time_point last_compute_time_;
};
