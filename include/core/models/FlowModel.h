#pragma once
#include "core/models/PacketModel.h"
#include <deque>
#include <functional>
#include <string>
#include <vector>

// ── TCP state machine ─────────────────────────────────────────────────────

enum class TCPState {
  CLOSED,
  LISTEN,
  SYN_SENT,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  CLOSE_WAIT,
  CLOSING,
  LAST_ACK,
  TIME_WAIT
};

std::string tcpStateToString(TCPState s);

// ── 5-tuple flow key with hashing ────────────────────────────────────────

struct FlowKey {
  std::string src_ip;
  std::string dst_ip;
  uint16_t src_port{0};
  uint16_t dst_port{0};
  Protocol protocol{Protocol::UNKNOWN};

  bool operator==(const FlowKey &o) const noexcept {
    return src_ip == o.src_ip && dst_ip == o.dst_ip && src_port == o.src_port &&
           dst_port == o.dst_port && protocol == o.protocol;
  }
};

namespace std {
template <> struct hash<FlowKey> {
  std::size_t operator()(const FlowKey &k) const noexcept {
    std::size_t h = 0;
    auto mix = [&](std::size_t v) {
      h ^= v + 0x9e3779b9 + (h << 6) + (h >> 2);
    };
    mix(std::hash<std::string>{}(k.src_ip));
    mix(std::hash<std::string>{}(k.dst_ip));
    mix(std::hash<uint16_t>{}(k.src_port));
    mix(std::hash<uint16_t>{}(k.dst_port));
    mix(std::hash<int>{}(static_cast<int>(k.protocol)));
    return h;
  }
};
} // namespace std

// ── Per-flow statistics ───────────────────────────────────────────────────

struct FlowStats {
  uint64_t packet_count{0};
  uint64_t byte_count{0};
  uint64_t retransmissions{0};
  uint64_t dropped_estimate{0};
  double rtt_ms{0.0};
  uint32_t fwd_last_seq{0};
  uint32_t rev_last_seq{0};
  uint32_t last_ack_seen{0};
  uint64_t last_pkt_snapshot{0};
  uint64_t last_retx_snapshot{0};
};

// ── Flow ──────────────────────────────────────────────────────────────────

struct Flow {
  uint32_t flow_id{0};
  FlowKey key;
  TCPState tcp_state{TCPState::CLOSED};
  FlowStats stats;

  std::deque<uint64_t> packet_ids;

  double first_seen{0.0};
  double last_seen{0.0};
  bool is_active{true};

  /// Time-stamped state transitions for the TCP diagram.
  std::vector<std::pair<double, TCPState>> state_history;
};
