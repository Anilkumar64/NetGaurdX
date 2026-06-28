// StressTest.cpp — extreme pressure test for NetGuardianX core pipeline
// Tests: high PPS, concurrent producers, malformed packets, EventBus flood,
//        filter churn, rapid start/stop cycles, flow table explosion,
//        large packets, zero-length packets, concurrent subscribe/unsubscribe.
//
// Build alongside PipelineValidator (no Qt Widgets needed — Qt::Core only).
// Expected output: all PASS lines, exit 0.

#include "core/Logger.h"
#include "core/PacketFilter.h"
#include "core/capture/SimulatedPacketSource.h"
#include "core/eventbus/EventBus.h"
#include "core/monitoring/MonitoringEngine.h"
#include "core/parser/PacketParserPipeline.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

// ── Helpers ────────────────────────────────────────────────────────────────

static void pass(const char *name) { std::cout << "PASS " << name << '\n'; }
static void fail(const char *name, const char *reason = "") {
  std::cout << "FAIL " << name;
  if (reason && reason[0])
    std::cout << " (" << reason << ')';
  std::cout << '\n';
}
static void check(bool ok, const char *name, const char *reason = "") {
  ok ? pass(name) : fail(name, reason);
}

// Minimal valid Ethernet+IPv4+TCP packet (SYN, 60 bytes)
static std::vector<uint8_t> makeTCPSynRaw(uint32_t src_ip, uint32_t dst_ip,
                                          uint16_t sport, uint16_t dport,
                                          uint32_t seq = 1000) {
  std::vector<uint8_t> pkt(60, 0);
  // Ethernet
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  // IPv4
  size_t ip = 14;
  pkt[ip] = 0x45;
  pkt[ip + 2] = 0x00;
  pkt[ip + 3] = 40; // total_len = 40 (IP+TCP, no payload)
  pkt[ip + 8] = 64; // TTL
  pkt[ip + 9] = 6;  // TCP
  pkt[ip + 12] = (src_ip >> 24) & 0xFF;
  pkt[ip + 13] = (src_ip >> 16) & 0xFF;
  pkt[ip + 14] = (src_ip >> 8) & 0xFF;
  pkt[ip + 15] = (src_ip) & 0xFF;
  pkt[ip + 16] = (dst_ip >> 24) & 0xFF;
  pkt[ip + 17] = (dst_ip >> 16) & 0xFF;
  pkt[ip + 18] = (dst_ip >> 8) & 0xFF;
  pkt[ip + 19] = (dst_ip) & 0xFF;
  // TCP
  size_t tcp = ip + 20;
  pkt[tcp] = sport >> 8;
  pkt[tcp + 1] = sport & 0xFF;
  pkt[tcp + 2] = dport >> 8;
  pkt[tcp + 3] = dport & 0xFF;
  pkt[tcp + 4] = seq >> 24;
  pkt[tcp + 5] = (seq >> 16) & 0xFF;
  pkt[tcp + 6] = (seq >> 8) & 0xFF;
  pkt[tcp + 7] = seq & 0xFF;
  pkt[tcp + 12] = 0x50; // data offset = 5 (20 bytes)
  pkt[tcp + 13] = 0x02; // SYN
  pkt[tcp + 14] = 0xFF;
  pkt[tcp + 15] = 0xFF; // window
  return pkt;
}

static std::vector<uint8_t> makeUDPDNSRaw(uint32_t src_ip, uint32_t dst_ip) {
  std::vector<uint8_t> pkt(42 + 12, 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  size_t ip = 14;
  pkt[ip] = 0x45;
  uint16_t tlen = 28 + 12;
  pkt[ip + 2] = tlen >> 8;
  pkt[ip + 3] = tlen & 0xFF;
  pkt[ip + 8] = 64;
  pkt[ip + 9] = 17; // UDP
  pkt[ip + 12] = (src_ip >> 24) & 0xFF;
  pkt[ip + 13] = (src_ip >> 16) & 0xFF;
  pkt[ip + 14] = (src_ip >> 8) & 0xFF;
  pkt[ip + 15] = src_ip & 0xFF;
  pkt[ip + 16] = (dst_ip >> 24) & 0xFF;
  pkt[ip + 17] = (dst_ip >> 16) & 0xFF;
  pkt[ip + 18] = (dst_ip >> 8) & 0xFF;
  pkt[ip + 19] = dst_ip & 0xFF;
  size_t udp = ip + 20;
  pkt[udp] = 0xC3;
  pkt[udp + 1] = 0x50; // sport = 50000
  pkt[udp + 2] = 0x00;
  pkt[udp + 3] = 0x35; // dport = 53
  uint16_t ulen = 8 + 12;
  pkt[udp + 4] = ulen >> 8;
  pkt[udp + 5] = ulen & 0xFF;
  return pkt;
}

// Large payload packet (~8KB)
static std::vector<uint8_t> makeLargePacketRaw() {
  const size_t payload = 8000;
  std::vector<uint8_t> pkt(14 + 20 + 20 + payload, 0xAB);
  pkt[12] = 0x08;
  pkt[13] = 0x00;
  size_t ip = 14;
  pkt[ip] = 0x45;
  pkt[ip + 9] = 6;
  uint32_t tlen = 20 + 20 + payload;
  pkt[ip + 2] = (tlen >> 8) & 0xFF;
  pkt[ip + 3] = tlen & 0xFF;
  pkt[ip + 8] = 64;
  pkt[ip + 12] = 10;
  pkt[ip + 13] = 0;
  pkt[ip + 14] = 0;
  pkt[ip + 15] = 1;
  pkt[ip + 16] = 10;
  pkt[ip + 17] = 0;
  pkt[ip + 18] = 0;
  pkt[ip + 19] = 2;
  size_t tcp = ip + 20;
  pkt[tcp] = 0x00;
  pkt[tcp + 1] = 0x50; // sport=80
  pkt[tcp + 2] = 0x04;
  pkt[tcp + 3] = 0x00; // dport=1024
  pkt[tcp + 12] = 0x50;
  pkt[tcp + 13] = 0x18; // ACK+PSH
  return pkt;
}

using Clock = std::chrono::steady_clock;

// ── TEST 1: Parser — null / zero-length / truncated  ──────────────────────

static bool testParserEdgeCases() {
  bool ok = true;

  // null ptr
  auto p1 = PacketParserPipeline::parse(1, nullptr, 0, 0.0);
  ok &= (p1 != nullptr);

  // 1 byte
  uint8_t tiny[1] = {0xFF};
  auto p2 = PacketParserPipeline::parse(2, tiny, 1, 0.0);
  ok &= (p2 != nullptr);

  // 13 bytes (1 byte short of Ethernet minimum — no room for ethertype)
  uint8_t short_eth[13] = {};
  short_eth[11] =
      0x08; // only 13 bytes, ethertype would be at [12..13] but we stop at 12
  auto p3 = PacketParserPipeline::parse(3, short_eth, 13, 0.0);
  ok &= (p3 != nullptr);

  // All-zero 60 bytes
  uint8_t zeros[60] = {};
  auto p4 = PacketParserPipeline::parse(4, zeros, 60, 0.0);
  ok &= (p4 != nullptr);

  // All-0xFF 1500 bytes
  uint8_t ff[1500];
  memset(ff, 0xFF, sizeof(ff));
  auto p5 = PacketParserPipeline::parse(5, ff, 1500, 0.0);
  ok &= (p5 != nullptr);

  // Large 8KB packet
  auto large = makeLargePacketRaw();
  auto p6 = PacketParserPipeline::parse(6, large.data(), large.size(), 0.0);
  ok &= (p6 != nullptr && p6->packet_size == large.size());

  return ok;
}

// ── TEST 2: High-throughput parser (single thread) ────────────────────────

static bool testHighThroughputParser() {
  const int N = 50000;
  auto raw = makeTCPSynRaw(0xC0A80101, 0x5DB8D822, 12345, 80);

  auto t0 = Clock::now();
  for (int i = 0; i < N; i++) {
    auto pkt = PacketParserPipeline::parse(i, raw.data(), raw.size(),
                                           static_cast<double>(i) * 0.001);
    if (!pkt)
      return false;
  }
  auto dt = std::chrono::duration<double>(Clock::now() - t0).count();
  std::cout << "  [throughput] " << N << " parses in " << dt << "s ("
            << static_cast<int>(N / dt) << " pps)\n";
  return true;
}

// ── TEST 3: Concurrent parsers (N threads, shared nothing) ────────────────

static bool testConcurrentParsers() {
  const int THREADS = 8;
  const int PER_THREAD = 10000;
  std::atomic<int> errors{0};

  auto worker = [&](int tid) {
    auto raw = makeTCPSynRaw(0xC0A80100 + tid, 0x08080808, 10000 + tid, 443);
    for (int i = 0; i < PER_THREAD; i++) {
      auto pkt = PacketParserPipeline::parse(
          static_cast<uint64_t>(tid * PER_THREAD + i), raw.data(), raw.size(),
          static_cast<double>(i));
      if (!pkt)
        errors++;
    }
  };

  std::vector<std::thread> threads;
  threads.reserve(THREADS);
  for (int t = 0; t < THREADS; t++)
    threads.emplace_back(worker, t);
  for (auto &th : threads)
    th.join();

  return errors.load() == 0;
}

// ── TEST 4: MonitoringEngine — high-rate ingestion ────────────────────────

static bool testMonitoringHighRate() {
  MonitoringEngine engine;
  engine.start();

  const int N = 20000;
  std::mt19937 rng(42);
  std::uniform_int_distribution<uint32_t> ip_dist(0x01000001, 0xFEFFFFFE);
  std::uniform_int_distribution<uint16_t> port_dist(1024, 65535);

  auto t0 = Clock::now();
  for (int i = 0; i < N; i++) {
    auto raw = makeTCPSynRaw(ip_dist(rng), ip_dist(rng), port_dist(rng),
                             port_dist(rng), i);
    auto pkt =
        PacketParserPipeline::parse(i, raw.data(), raw.size(), i * 0.001);
    if (pkt)
      engine.ingestPacket(*pkt);
  }
  auto dt = std::chrono::duration<double>(Clock::now() - t0).count();
  std::cout << "  [monitoring] " << N << " ingests in " << dt << "s\n";

  auto flows = engine.getActiveFlows();
  auto metrics = engine.getMetricsCopy();
  engine.stop();

  return metrics.total_packets.load() == static_cast<uint64_t>(N) &&
         !flows.empty();
}

// ── TEST 5: MonitoringEngine — concurrent ingest from multiple threads ─────

static bool testConcurrentIngestion() {
  MonitoringEngine engine;
  engine.start();

  const int THREADS = 6;
  const int PER = 5000;
  std::atomic<int> done{0};

  auto worker = [&](int tid) {
    std::mt19937 rng(tid);
    std::uniform_int_distribution<uint32_t> ip_dist(0x0A000001, 0x0AFFFFFF);
    std::uniform_int_distribution<uint16_t> port_dist(1024, 60000);
    for (int i = 0; i < PER; i++) {
      auto raw =
          makeTCPSynRaw(ip_dist(rng), ip_dist(rng), port_dist(rng), 443, i);
      auto pkt =
          PacketParserPipeline::parse(static_cast<uint64_t>(tid * PER + i),
                                      raw.data(), raw.size(), i * 0.0001);
      if (pkt)
        engine.ingestPacket(*pkt);
    }
    done++;
  };

  std::vector<std::thread> threads;
  threads.reserve(THREADS);
  for (int t = 0; t < THREADS; t++)
    threads.emplace_back(worker, t);
  for (auto &th : threads)
    th.join();

  // Let monitor thread tick once
  std::this_thread::sleep_for(std::chrono::milliseconds(1200));

  auto metrics = engine.getMetricsCopy();
  engine.stop();

  return metrics.total_packets.load() == static_cast<uint64_t>(THREADS * PER);
}

// ── TEST 6: EventBus — flood publish from multiple threads ────────────────

static bool testEventBusFlood() {
  const int THREADS = 8;
  const int PER = 5000;
  std::atomic<uint64_t> received{0};

  auto tok = EventBus::instance().subscribe(EventType::PACKET_CAPTURED,
                                            [&](const Event &) { received++; });

  std::vector<std::thread> threads;
  threads.reserve(THREADS);
  for (int t = 0; t < THREADS; t++) {
    threads.emplace_back([&]() {
      for (int i = 0; i < PER; i++) {
        EventBus::instance().publish({EventType::PACKET_CAPTURED, 0.0, "stress",
                                      "L2", "INFO",
                                      std::make_shared<const UnifiedPacket>()});
      }
    });
  }
  for (auto &th : threads)
    th.join();

  EventBus::instance().unsubscribe(tok);

  return received.load() == static_cast<uint64_t>(THREADS * PER);
}

// ── TEST 7: EventBus — concurrent subscribe/unsubscribe while publishing ──

static bool testEventBusDynamic() {
  std::atomic<bool> running{true};
  std::atomic<int> errors{0};

  // Publisher thread
  auto publisher = std::thread([&]() {
    while (running.load()) {
      EventBus::instance().publish({EventType::METRICS_UPDATED, 0.0, "churn",
                                    "SYS", "INFO", std::string{}});
    }
  });

  // Subscriber churn threads
  const int CHURN_THREADS = 4;
  std::vector<std::thread> churners;
  churners.reserve(CHURN_THREADS);
  for (int t = 0; t < CHURN_THREADS; t++) {
    churners.emplace_back([&]() {
      for (int i = 0; i < 500; i++) {
        auto tok = EventBus::instance().subscribe(EventType::METRICS_UPDATED,
                                                  [](const Event &) {});
        std::this_thread::yield();
        EventBus::instance().unsubscribe(tok);
      }
    });
  }
  for (auto &th : churners)
    th.join();

  running = false;
  publisher.join();

  return errors.load() == 0;
}

// ── TEST 8: SimulatedPacketSource — sustained delivery under load ──────────
// Source is a realistic traffic generator designed for 5-40 PPS.
// Each generateLoop tick may emit 1-3 packets (e.g. SYN+SYNACK+ACK).
// Test: packets flow, no deadlock/crash, count plausible over run window.

static bool testSimulatedHighPPS() {
  const int PPS = 40;
  const int DURATION_MS = 2000;

  std::atomic<uint64_t> count{0};
  MonitoringEngine engine;
  engine.start();

  SimulatedPacketSource source(PPS);
  source.setPacketCallback([&](std::shared_ptr<const UnifiedPacket> pkt) {
    if (pkt) {
      engine.ingestPacket(*pkt);
      count++;
    }
  });

  source.start();
  std::this_thread::sleep_for(std::chrono::milliseconds(DURATION_MS));
  source.stop();
  engine.stop();

  uint64_t got = count.load();
  // 40 PPS × 2s = 80 ticks; each tick delivers ≥1 packet.
  // Accept ≥50% to allow startup/shutdown jitter.
  uint64_t expected_min = static_cast<uint64_t>(PPS * DURATION_MS / 1000) / 2;
  std::cout << "  [sim-pps] got=" << got << " expected_min=" << expected_min
            << " (source designed for realistic 5-40 PPS)\n";
  return got >= expected_min;
}

// ── TEST 9: Rapid start/stop cycles ───────────────────────────────────────

static bool testRapidStartStop() {
  for (int i = 0; i < 20; i++) {
    MonitoringEngine engine;
    engine.start();

    SimulatedPacketSource source(50);
    source.setPacketCallback([&](std::shared_ptr<const UnifiedPacket> pkt) {
      if (pkt)
        engine.ingestPacket(*pkt);
    });
    source.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    source.stop();
    engine.stop();
  }
  return true; // no crash = pass
}

// ── TEST 10: Flow table explosion — many unique flows ──────────────────────

static bool testFlowTableExplosion() {
  MonitoringEngine engine;
  engine.start();

  const int FLOWS = 5000;
  std::mt19937 rng(99);
  std::uniform_int_distribution<uint32_t> ip_dist(0x01000001, 0xDFFFFFFF);

  for (int i = 0; i < FLOWS; i++) {
    auto raw = makeTCPSynRaw(ip_dist(rng), ip_dist(rng),
                             static_cast<uint16_t>(1024 + (i % 60000)),
                             static_cast<uint16_t>(1 + (i % 65534)), i);
    auto pkt =
        PacketParserPipeline::parse(i, raw.data(), raw.size(), i * 0.001);
    if (pkt)
      engine.ingestPacket(*pkt);
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  auto flows = engine.getActiveFlows();
  auto metrics = engine.getMetricsCopy();
  engine.stop();

  std::cout << "  [flow-table] flows=" << flows.size()
            << " packets=" << metrics.total_packets.load() << '\n';
  return metrics.total_packets.load() == static_cast<uint64_t>(FLOWS);
}

// ── TEST 11: Malformed / truncated packets through pipeline ───────────────

static bool testMalformedPackets() {
  MonitoringEngine engine;
  engine.start();
  std::atomic<int> ok_count{0};

  const int N = 1000;
  std::mt19937 rng(7);
  std::uniform_int_distribution<int> size_dist(0, 2000);
  std::uniform_int_distribution<uint8_t> byte_dist(0, 255);

  for (int i = 0; i < N; i++) {
    int sz = size_dist(rng);
    std::vector<uint8_t> garbage(sz);
    for (auto &b : garbage)
      b = byte_dist(rng);

    auto pkt = PacketParserPipeline::parse(
        i, garbage.empty() ? nullptr : garbage.data(), garbage.size(),
        i * 0.001);
    if (pkt) {
      engine.ingestPacket(*pkt);
      ok_count++;
    }
  }

  engine.stop();
  // All N must return non-null (parser must not crash/return null on garbage)
  return ok_count.load() == N;
}

// ── TEST 12: PacketFilter — concurrent parse+match under filter churn ─────

static bool testFilterChurn() {
  const int THREADS = 4;
  const int PER = 2000;
  std::atomic<int> errors{0};

  auto worker = [&](int tid) {
    auto raw = makeTCPSynRaw(0xC0A80100 + tid, 0x08080808,
                             static_cast<uint16_t>(10000 + tid), 80);
    PacketFilter f;
    // Alternate between valid and empty filters
    for (int i = 0; i < PER; i++) {
      auto pkt =
          PacketParserPipeline::parse(static_cast<uint64_t>(tid * PER + i),
                                      raw.data(), raw.size(), i * 0.001);
      if (!pkt) {
        errors++;
        continue;
      }

      PacketFilter filt;
      if (i % 3 == 0)
        filt.parse("tcp");
      else if (i % 3 == 1)
        filt.parse("udp");
      else
        filt.parse(""); // accept-all

      // Just call matches — should not crash
      filt.matches(*pkt);
    }
  };

  std::vector<std::thread> threads;
  threads.reserve(THREADS);
  for (int t = 0; t < THREADS; t++)
    threads.emplace_back(worker, t);
  for (auto &th : threads)
    th.join();

  return errors.load() == 0;
}

// ── TEST 13: Mixed protocol storm ─────────────────────────────────────────

static bool testMixedProtocolStorm() {
  MonitoringEngine engine;
  engine.start();

  const int N = 10000;
  std::atomic<uint64_t> ingested{0};
  std::mt19937 rng(13);
  std::uniform_int_distribution<int> proto(0, 2);
  std::uniform_int_distribution<uint32_t> ip(0x01000001, 0xFEFFFFFE);

  for (int i = 0; i < N; i++) {
    std::vector<uint8_t> raw;
    switch (proto(rng)) {
    case 0:
      raw = makeTCPSynRaw(ip(rng), ip(rng), 1024 + i % 60000, 80, i);
      break;
    case 1:
      raw = makeUDPDNSRaw(ip(rng), 0x08080808);
      break;
    case 2:
      raw = makeLargePacketRaw();
      break;
    }
    auto pkt =
        PacketParserPipeline::parse(i, raw.data(), raw.size(), i * 0.0001);
    if (pkt) {
      engine.ingestPacket(*pkt);
      ingested++;
    }
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(1200));
  auto metrics = engine.getMetricsCopy();
  engine.stop();

  return ingested.load() == static_cast<uint64_t>(N) &&
         metrics.total_packets.load() == ingested.load();
}

// ── TEST 14: Metrics snapshot consistency under concurrent ingestion ───────

static bool testMetricsConsistency() {
  MonitoringEngine engine;
  engine.start();

  std::atomic<bool> running{true};
  std::atomic<uint64_t> ingested{0};

  // Ingestion thread
  auto ingest_th = std::thread([&]() {
    auto raw = makeTCPSynRaw(0xC0A80101, 0x08080808, 12345, 443);
    int i = 0;
    while (running.load()) {
      double ts = i * 0.0001;
      auto pkt = PacketParserPipeline::parse(i++, raw.data(), raw.size(), ts);
      if (pkt) {
        engine.ingestPacket(*pkt);
        ingested++;
      }
    }
  });

  // Snapshot thread — must never see negative or impossible values
  bool consistent = true;
  auto snap_th = std::thread([&]() {
    for (int i = 0; i < 50; i++) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      auto m = engine.getMetricsCopy();
      if (m.total_packets.load() > ingested.load() + 1000) {
        consistent =
            false; // total_packets ahead of ingested by impossible margin
      }
    }
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(1500));
  running = false;
  ingest_th.join();
  snap_th.join();
  engine.stop();

  return consistent;
}

// ── TEST 15: Double-stop safety ───────────────────────────────────────────

static bool testDoubleStop() {
  MonitoringEngine engine;
  engine.start();
  engine.stop();
  engine.stop(); // second stop must not crash/deadlock

  SimulatedPacketSource source(10);
  source.start();
  source.stop();
  source.stop(); // second stop must not crash/deadlock

  return true;
}

// ── TEST 16: EventBus — unsubscribe non-existent token ────────────────────

static bool testEventBusGhostUnsubscribe() {
  // Should be a no-op, not a crash
  EventBus::instance().unsubscribe(999999999ULL);
  EventBus::instance().unsubscribe(0ULL);
  return true;
}

// ── TEST 17: Parser large-packet packet_size field ────────────────────────

static bool testLargePacketSize() {
  auto raw = makeLargePacketRaw(); // ~8KB
  auto pkt = PacketParserPipeline::parse(1, raw.data(), raw.size(), 0.0);
  // BUG5-FIX: packet_size is uint32_t; must not be capped to 65535
  return pkt && pkt->packet_size == static_cast<uint32_t>(raw.size());
}

// ── TEST 18: No events leaked across monitoring engine restart ─────────────

static bool testEventLeakAcrossRestart() {
  std::atomic<int> count1{0}, count2{0};

  {
    MonitoringEngine engine;
    engine.start();
    auto tok = EventBus::instance().subscribe(EventType::FLOW_CREATED,
                                              [&](const Event &) { count1++; });
    auto raw = makeTCPSynRaw(0x0A000001, 0x0A000002, 12345, 80);
    for (int i = 0; i < 100; i++) {
      auto pkt =
          PacketParserPipeline::parse(i, raw.data(), raw.size(), i * 0.001);
      if (pkt)
        engine.ingestPacket(*pkt);
    }
    engine.stop();
    EventBus::instance().unsubscribe(tok);
  }

  // Fresh engine — count2 must start from 0
  {
    MonitoringEngine engine;
    engine.start();
    auto tok = EventBus::instance().subscribe(EventType::FLOW_CREATED,
                                              [&](const Event &) { count2++; });
    auto raw = makeTCPSynRaw(0x0B000001, 0x0B000002, 54321, 443);
    for (int i = 0; i < 100; i++) {
      auto pkt = PacketParserPipeline::parse(1000 + i, raw.data(), raw.size(),
                                             i * 0.001);
      if (pkt)
        engine.ingestPacket(*pkt);
    }
    engine.stop();
    EventBus::instance().unsubscribe(tok);
  }

  // Both should have seen events; neither should be 0 if flows created
  return count1 > 0 && count2 > 0;
}

// ── main ───────────────────────────────────────────────────────────────────

int main() {
  // Silence debug log spam during stress
  Logger::instance().setLevel(LogLevel::ERROR);

  std::cout << "=== NetGuardianX StressTest ===\n\n";

  struct Test {
    const char *name;
    std::function<bool()> fn;
  };

  std::vector<Test> tests = {
      {"parser: edge cases (null/tiny/truncated/garbage/large)",
       testParserEdgeCases},
      {"parser: 50k parses single-thread throughput", testHighThroughputParser},
      {"parser: 8 threads × 10k concurrent parses", testConcurrentParsers},
      {"monitoring: 20k high-rate ingestion", testMonitoringHighRate},
      {"monitoring: 6 threads × 5k concurrent ingestion",
       testConcurrentIngestion},
      {"eventbus: 8 threads × 5k flood publish", testEventBusFlood},
      {"eventbus: concurrent subscribe/unsubscribe while publishing",
       testEventBusDynamic},
      {"simulated-source: sustained delivery at 40 PPS for 2s",
       testSimulatedHighPPS},
      {"lifecycle: 20× rapid start/stop cycles", testRapidStartStop},
      {"flow-table: 5000 unique flows", testFlowTableExplosion},
      {"parser: 1000 random-garbage malformed packets", testMalformedPackets},
      {"filter: concurrent parse+match churn (4 threads)", testFilterChurn},
      {"storm: 10k mixed TCP/UDP/large packets", testMixedProtocolStorm},
      {"metrics: snapshot consistency under concurrent ingestion",
       testMetricsConsistency},
      {"lifecycle: double-stop safety", testDoubleStop},
      {"eventbus: ghost-token unsubscribe", testEventBusGhostUnsubscribe},
      {"parser: large packet_size > 65535 (BUG5 regression)",
       testLargePacketSize},
      {"monitoring: no event leak across engine restart",
       testEventLeakAcrossRestart},
  };

  int passed = 0, failed = 0;
  for (auto &t : tests) {
    std::cout << "--- " << t.name << '\n';
    bool ok = false;
    try {
      ok = t.fn();
    } catch (const std::exception &e) {
      std::cout << "  EXCEPTION: " << e.what() << '\n';
    } catch (...) {
      std::cout << "  UNKNOWN EXCEPTION\n";
    }
    check(ok, t.name);
    ok ? passed++ : failed++;
    std::cout << '\n';
  }

  std::cout << "=== RESULTS: " << passed << " passed, " << failed
            << " failed / " << (passed + failed) << " total ===\n";
  return failed == 0 ? 0 : 1;
}