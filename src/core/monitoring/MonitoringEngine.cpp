#include "core/monitoring/MonitoringEngine.h"
#include "core/Logger.h"
#include "core/eventbus/EventBus.h"
#include <algorithm>
#include <tuple>

namespace {
constexpr std::size_t kMaxPacketIdsPerFlow = 1000;
constexpr double kClosedFlowRetentionSeconds = 60.0;

FlowKey normalizedFlowKey(const UnifiedPacket &pkt) {
  FlowKey forward{pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port,
                  pkt.protocol};
  FlowKey reverse{pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port,
                  pkt.protocol};
  const auto lhs = std::tie(forward.src_ip, forward.src_port, forward.dst_ip,
                            forward.dst_port);
  const auto rhs = std::tie(reverse.src_ip, reverse.src_port, reverse.dst_ip,
                            reverse.dst_port);
  return lhs <= rhs ? forward : reverse;
}

void appendPacketId(Flow &flow, uint64_t packet_id) {
  if (flow.packet_ids.size() >= kMaxPacketIdsPerFlow) {
    flow.packet_ids.pop_front();
  }
  flow.packet_ids.push_back(packet_id);
}

uint32_t flowIdFromKey(const FlowKey &key) {
  uint32_t flow_id = static_cast<uint32_t>(std::hash<FlowKey>{}(key));
  return flow_id == 0 ? 1 : flow_id;
}

bool isForwardPacket(const Flow &flow, const UnifiedPacket &pkt) {
  return pkt.src_ip == flow.key.src_ip && pkt.src_port == flow.key.src_port;
}

void updateDirectionalSequenceStats(Flow &flow, const UnifiedPacket &pkt) {
  if (!pkt.has_tcp || pkt.seq_num == 0) {
    return;
  }

  uint32_t &last_seq = isForwardPacket(flow, pkt) ? flow.stats.fwd_last_seq
                                                  : flow.stats.rev_last_seq;

  if (last_seq != 0 && pkt.seq_num <= last_seq && pkt.tcp_flags != 0x10) {
    flow.stats.retransmissions++;
  }
  last_seq = std::max(last_seq, pkt.seq_num);
}
} // namespace

void MonitoringEngine::start() {
  if (running_.exchange(true)) {
    return;
  }
  last_compute_time_ = std::chrono::steady_clock::now();
  last_total_packets_ = 0;
  last_total_bytes_ = 0;
  monitor_thread_ = std::thread(&MonitoringEngine::monitorLoop, this);
}

void MonitoringEngine::stop() {
  running_ = false;
  if (monitor_thread_.joinable())
    monitor_thread_.join();
}

void MonitoringEngine::ingestPacket(const UnifiedPacket &pkt) {
  metrics_.total_packets++;
  metrics_.total_bytes += pkt.packet_size;
  Logger::instance().log(LogLevel::DEBUG, "MONITOR",
                         "ingested packet id=" + std::to_string(pkt.id));
  updateFlow(pkt);
}

void MonitoringEngine::updateFlow(const UnifiedPacket &pkt) {
  FlowKey key = normalizedFlowKey(pkt);
  uint32_t flow_id = pkt.flow_id != 0 ? pkt.flow_id : flowIdFromKey(key);

  std::lock_guard<std::mutex> lock(flows_mutex_);
  auto it = flows_.find(flow_id);
  if (it == flows_.end()) {
    Flow flow{};
    flow.flow_id = flow_id;
    flow.key = key;
    flow.tcp_state = TCPState::CLOSED;
    flow.first_seen = pkt.timestamp;
    flow.last_seen = pkt.timestamp;
    flow.is_active = true;
    flow.stats.packet_count = 1;
    flow.stats.byte_count = pkt.packet_size;
    appendPacketId(flow, pkt.id);
    updateDirectionalSequenceStats(flow, pkt);
    updateTCPState(flow, pkt);
    flows_[flow_id] = flow;
    metrics_.active_flows.fetch_add(1);
    EventBus::instance().publish({EventType::FLOW_CREATED, pkt.timestamp,
                                  "New flow", "L4", "INFO", flows_[flow_id]});
  } else {
    Flow &flow = it->second;
    flow.last_seen = pkt.timestamp;
    flow.stats.packet_count++;
    flow.stats.byte_count += pkt.packet_size;
    appendPacketId(flow, pkt.id);
    updateDirectionalSequenceStats(flow, pkt);
    updateTCPState(flow, pkt);
    EventBus::instance().publish({EventType::FLOW_UPDATED, pkt.timestamp,
                                  "Flow updated", "L4", "INFO", flow});
  }
}

void MonitoringEngine::updateTCPState(Flow &flow, const UnifiedPacket &pkt) {
  if (!pkt.has_tcp)
    return;

  TCPState old_state = flow.tcp_state;

  if (pkt.tcp_flags & 0x04) { // RST
    flow.tcp_state = TCPState::CLOSED;
    EventBus::instance().publish({EventType::ALERT_TCP_RESET, pkt.timestamp,
                                  "TCP Reset", "L4", "WARN", flow.flow_id});
  } else if (old_state == TCPState::CLOSED && (pkt.tcp_flags & 0x02)) {
    flow.tcp_state = TCPState::SYN_SENT;
  } else if (old_state == TCPState::SYN_SENT &&
             (pkt.tcp_flags & 0x12) == 0x12) {
    flow.tcp_state = TCPState::SYN_RECEIVED;
  } else if (old_state == TCPState::SYN_RECEIVED && (pkt.tcp_flags & 0x10)) {
    flow.tcp_state = TCPState::ESTABLISHED;
  } else if (old_state == TCPState::CLOSED && (pkt.tcp_flags & 0x10)) {
    flow.tcp_state = TCPState::ESTABLISHED;
  } else if (old_state == TCPState::ESTABLISHED && (pkt.tcp_flags & 0x01)) {
    flow.tcp_state = TCPState::FIN_WAIT_1;
  } else if (old_state == TCPState::FIN_WAIT_1 &&
             (pkt.tcp_flags & 0x11) == 0x11) {
    flow.tcp_state = TCPState::TIME_WAIT;
  }

  if (old_state != flow.tcp_state) {
    flow.state_history.push_back({pkt.timestamp, flow.tcp_state});
    if (flow.tcp_state == TCPState::CLOSED) {
      flow.is_active = false;
      uint32_t active = metrics_.active_flows.load();
      while (active > 0 &&
             !metrics_.active_flows.compare_exchange_weak(active, active - 1)) {
      }
      EventBus::instance().publish({EventType::FLOW_CLOSED, pkt.timestamp,
                                    "Flow closed", "L4", "INFO", flow.flow_id});
    }
  }
  flow.stats.last_ack_seen = std::max(flow.stats.last_ack_seen, pkt.ack_num);
}

NetworkMetrics MonitoringEngine::getMetricsCopy() const {
  NetworkMetrics snapshot;
  snapshot.packets_per_second.store(metrics_.packets_per_second.load());
  snapshot.bytes_per_second.store(metrics_.bytes_per_second.load());
  snapshot.dropped_packets.store(metrics_.dropped_packets.load());
  snapshot.total_packets.store(metrics_.total_packets.load());
  snapshot.total_bytes.store(metrics_.total_bytes.load());
  snapshot.avg_latency_ms.store(metrics_.avg_latency_ms.load());
  snapshot.retransmission_rate.store(metrics_.retransmission_rate.load());
  snapshot.active_flows.store(metrics_.active_flows.load());
  snapshot.active_threads.store(metrics_.active_threads.load());
  snapshot.capture_queue_size.store(metrics_.capture_queue_size.load());
  snapshot.processing_queue_size.store(metrics_.processing_queue_size.load());

  {
    std::lock_guard<std::mutex> lock(metrics_.history_mutex);
    snapshot.pps_history = metrics_.pps_history;
    snapshot.bps_history = metrics_.bps_history;
  }

  return snapshot;
}

std::vector<Flow> MonitoringEngine::getActiveFlows() const {
  std::vector<Flow> res;
  std::lock_guard<std::mutex> lock(flows_mutex_);
  for (const auto &kv : flows_)
    if (kv.second.is_active)
      res.push_back(kv.second);
  return res;
}

void MonitoringEngine::monitorLoop() {
  while (running_) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    detectAnomalies(); // detect BEFORE snapshots are updated
    computeMetrics();  // snapshots updated here
  }
}

void MonitoringEngine::computeMetrics() {
  auto now = std::chrono::steady_clock::now();
  double dt = std::chrono::duration<double>(now - last_compute_time_).count();
  if (dt < 0.001)
    dt = 1.0;

  uint64_t cur_pkts = metrics_.total_packets.load();
  uint64_t cur_bytes = metrics_.total_bytes.load();

  uint64_t delta_pkts = cur_pkts - last_total_packets_;
  uint64_t delta_bytes = cur_bytes - last_total_bytes_;

  metrics_.packets_per_second = static_cast<uint64_t>(delta_pkts / dt);
  metrics_.bytes_per_second = static_cast<uint64_t>(delta_bytes / dt);

  uint64_t retransmissions = 0;
  uint64_t packets = 0;
  {
    std::lock_guard<std::mutex> lock(flows_mutex_);
    double current_ts = std::chrono::duration<double>(
                            std::chrono::system_clock::now().time_since_epoch())
                            .count();
    for (auto it = flows_.begin(); it != flows_.end();) {
      if (!it->second.is_active &&
          (current_ts - it->second.last_seen > kClosedFlowRetentionSeconds)) {
        it = flows_.erase(it);
      } else {
        // Delta-based: only count what happened since last interval
        uint64_t flow_pkts = it->second.stats.packet_count;
        uint64_t flow_retx = it->second.stats.retransmissions;

        packets += flow_pkts > it->second.stats.last_pkt_snapshot
                       ? flow_pkts - it->second.stats.last_pkt_snapshot
                       : 0;
        retransmissions += flow_retx > it->second.stats.last_retx_snapshot
                               ? flow_retx - it->second.stats.last_retx_snapshot
                               : 0;

        it->second.stats.last_pkt_snapshot = flow_pkts;
        it->second.stats.last_retx_snapshot = flow_retx;
        ++it;
      }
    }
    metrics_.active_flows.store(static_cast<uint32_t>(
        std::count_if(flows_.begin(), flows_.end(),
                      [](const auto &kv) { return kv.second.is_active; })));
  }

  metrics_.retransmission_rate.store(
      packets == 0 ? 0.0
                   : static_cast<double>(retransmissions) /
                         static_cast<double>(packets));

  const double timestamp =
      std::chrono::duration<double>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  {
    std::lock_guard<std::mutex> lock(metrics_.history_mutex);
    metrics_.pps_history.push_back(
        {timestamp, metrics_.packets_per_second.load()});
    metrics_.bps_history.push_back(
        {timestamp, metrics_.bytes_per_second.load()});
    if (metrics_.pps_history.size() > 300)
      metrics_.pps_history.pop_front();
    if (metrics_.bps_history.size() > 300)
      metrics_.bps_history.pop_front();
  }

  last_total_packets_ = cur_pkts;
  last_total_bytes_ = cur_bytes;
  last_compute_time_ = now;

  EventBus::instance().publish({EventType::METRICS_UPDATED, 0.0,
                                "Metrics updated", "APP", "INFO",
                                std::string{}});
}

void MonitoringEngine::detectAnomalies() {
  std::lock_guard<std::mutex> lock(flows_mutex_);

  for (const auto &kv : flows_) {
    const Flow &flow = kv.second;

    // Use delta since last interval, not lifetime totals
    uint64_t delta_pkts =
        flow.stats.packet_count > flow.stats.last_pkt_snapshot
            ? flow.stats.packet_count - flow.stats.last_pkt_snapshot
            : 0;
    uint64_t delta_retx =
        flow.stats.retransmissions > flow.stats.last_retx_snapshot
            ? flow.stats.retransmissions - flow.stats.last_retx_snapshot
            : 0;

    if (delta_pkts == 0)
      continue;

    double rate =
        static_cast<double>(delta_retx) / static_cast<double>(delta_pkts);

    if (rate > 0.05) {
      EventBus::instance().publish({EventType::ALERT_HIGH_RETRANSMISSION, 0.0,
                                    "High retransmission rate", "L4", "WARN",
                                    flow.flow_id});
    }
  }
}