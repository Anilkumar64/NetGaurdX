#pragma once
#include <cstdint>
#include <deque>
#include <mutex>

struct BufferSnapshot
{
    double timestamp{0.0};
    uint64_t nic_rx_dropped{0};
    uint64_t nic_tx_dropped{0};
    uint64_t socket_buffer_usage{0};  // percentage 0-100
    uint64_t app_processing_queue{0}; // estimated queue depth
};

class BufferMonitor
{
public:
    /// Take a snapshot from /proc/net/dev and /proc/net/sockstat.
    BufferSnapshot snapshot();

    /// Return the full history of snapshots (thread-safe copy).
    std::deque<BufferSnapshot> getHistory() const;

private:
    std::deque<BufferSnapshot> history_;
    mutable std::mutex mutex_;

    // Rolling baseline for drop-counter delta computation
    uint64_t last_rx_drop_{0};
    uint64_t last_tx_drop_{0};
};
