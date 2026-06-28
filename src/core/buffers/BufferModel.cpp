#include "core/buffers/BufferModel.h"
#include <chrono>
#include <fstream>
#include <string>
#include <sstream>
#include <algorithm>
#include <cctype>

static double nowSec()
{
    return std::chrono::duration<double>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

BufferSnapshot BufferMonitor::snapshot()
{
    BufferSnapshot snap;
    snap.timestamp = nowSec();

    // Try to read /proc/net/dev for aggregate non-loopback drop counters.
    std::ifstream dev("/proc/net/dev");
    if (dev.is_open()) {
        std::string line;
        uint64_t total_rx_drop = 0;
        uint64_t total_tx_drop = 0;
        while (std::getline(dev, line)) {
            const auto colon = line.find(':');
            if (colon == std::string::npos) {
                continue;
            }

            std::string iface = line.substr(0, colon);
            iface.erase(std::remove_if(iface.begin(), iface.end(), [](unsigned char ch) {
                return std::isspace(ch) != 0;
            }), iface.end());
            if (iface.empty() || iface == "lo") {
                continue;
            }

            std::istringstream ss(line.substr(colon + 1));
            uint64_t rx_bytes = 0, rx_pkts = 0, rx_err = 0, rx_drop = 0;
            uint64_t tx_bytes = 0, tx_pkts = 0, tx_err = 0, tx_drop = 0;
            uint64_t dummy = 0;

            // fields: rx_bytes rx_pkts rx_err rx_drop rx_fifo rx_frame rx_compressed rx_multicast
            //         tx_bytes tx_pkts tx_err tx_drop ...
            if (!(ss >> rx_bytes >> rx_pkts >> rx_err >> rx_drop)) {
                continue;
            }
            for (int i = 0; i < 4; ++i) {
                ss >> dummy;
            }
            if (!(ss >> tx_bytes >> tx_pkts >> tx_err >> tx_drop)) {
                continue;
            }

            total_rx_drop += rx_drop;
            total_tx_drop += tx_drop;
        }

        snap.nic_rx_dropped = total_rx_drop >= last_rx_drop_ ? total_rx_drop - last_rx_drop_ : 0;
        snap.nic_tx_dropped = total_tx_drop >= last_tx_drop_ ? total_tx_drop - last_tx_drop_ : 0;
        last_rx_drop_ = total_rx_drop;
        last_tx_drop_ = total_tx_drop;
    }

    // Read /proc/net/sockstat for socket buffer usage estimate
    std::ifstream sockstat("/proc/net/sockstat");
    snap.socket_buffer_usage = 30; // default
    if (sockstat.is_open()) {
        std::string line;
        while (std::getline(sockstat, line)) {
            if (line.find("TCP:") != std::string::npos) {
                // "TCP: inuse N orphan N tw N alloc N mem N"
                std::string tok;
                std::istringstream ss(line);
                ss >> tok; // "TCP:"
                while (ss >> tok) {
                    if (tok == "mem") {
                        uint64_t mem;
                        if (ss >> mem)
                            snap.socket_buffer_usage = static_cast<uint64_t>(std::min<uint64_t>(mem / 10U, 100U));
                        break;
                    }
                }
                break;
            }
        }
    }

    snap.app_processing_queue = 5;

    std::lock_guard<std::mutex> lk(mutex_);
    history_.push_back(snap);
    // Keep last 300 snapshots (~5 min at 1/s)
    if (history_.size() > 300)
        history_.pop_front();
    return snap;
}

std::deque<BufferSnapshot> BufferMonitor::getHistory() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return history_;
}
