#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <utility>

// ── Network-wide counters ─────────────────────────────────────────────────

struct NetworkMetrics
{
    std::atomic<uint64_t> packets_per_second{0};
    std::atomic<uint64_t> bytes_per_second{0};
    std::atomic<uint64_t> dropped_packets{0};
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    std::atomic<double> avg_latency_ms{0.0};
    std::atomic<double> retransmission_rate{0.0};
    std::atomic<uint32_t> active_flows{0};
    std::atomic<uint32_t> active_threads{0};
    std::atomic<uint64_t> capture_queue_size{0};
    std::atomic<uint64_t> processing_queue_size{0};

    std::deque<std::pair<double, uint64_t>> pps_history;
    std::deque<std::pair<double, uint64_t>> bps_history;
    mutable std::mutex history_mutex;

    // Default-constructible
    NetworkMetrics() = default;

    // Copy constructor: atomics must be loaded individually.
    NetworkMetrics(const NetworkMetrics &o)
        : packets_per_second(o.packets_per_second.load()), bytes_per_second(o.bytes_per_second.load()), dropped_packets(o.dropped_packets.load()), total_packets(o.total_packets.load()), total_bytes(o.total_bytes.load()), avg_latency_ms(o.avg_latency_ms.load()), retransmission_rate(o.retransmission_rate.load()), active_flows(o.active_flows.load()), active_threads(o.active_threads.load()), capture_queue_size(o.capture_queue_size.load()), processing_queue_size(o.processing_queue_size.load())
    {
        std::lock_guard<std::mutex> lock(o.history_mutex);
        pps_history = o.pps_history;
        bps_history = o.bps_history;
    }

    // Copy-assign
    NetworkMetrics &operator=(const NetworkMetrics &o)
    {
        if (this == &o)
            return *this;
        packets_per_second.store(o.packets_per_second.load());
        bytes_per_second.store(o.bytes_per_second.load());
        dropped_packets.store(o.dropped_packets.load());
        total_packets.store(o.total_packets.load());
        total_bytes.store(o.total_bytes.load());
        avg_latency_ms.store(o.avg_latency_ms.load());
        retransmission_rate.store(o.retransmission_rate.load());
        active_flows.store(o.active_flows.load());
        active_threads.store(o.active_threads.load());
        capture_queue_size.store(o.capture_queue_size.load());
        processing_queue_size.store(o.processing_queue_size.load());
        {
            std::scoped_lock lock(history_mutex, o.history_mutex);
            pps_history = o.pps_history;
            bps_history = o.bps_history;
        }
        return *this;
    }
};

// ── Health indicators ─────────────────────────────────────────────────────

enum class HealthStatus
{
    HEALTHY,
    DEGRADED,
    DOWN
};

struct SystemHealth
{
    HealthStatus overall{HealthStatus::HEALTHY};
    HealthStatus http_health{HealthStatus::HEALTHY};
    HealthStatus dns_health{HealthStatus::HEALTHY};
    HealthStatus network_health{HealthStatus::HEALTHY};
    std::string status_message{"OK"};
};
