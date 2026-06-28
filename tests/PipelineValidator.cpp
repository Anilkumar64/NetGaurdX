#include "core/Logger.h"
#include "core/capture/SimulatedPacketSource.h"
#include "core/eventbus/EventBus.h"
#include "core/monitoring/MonitoringEngine.h"
#include "core/parser/PacketParserPipeline.h"
#include <algorithm>
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>

namespace {

std::vector<uint8_t> buildTlsClientHelloPacket() {
  std::vector<uint8_t> tls = {0x16, 0x03, 0x03, 0x00, 0x43, // TLS record header
                              0x01, 0x00, 0x00, 0x3f, // ClientHello handshake
                              0x03, 0x03,             // legacy_version
                              0,    0,    0,    0,    0,    0,   0,   0,   0,
                              0,    0,    0,    0,    0,    0,   0, // random
                              0,    0,    0,    0,    0,    0,   0,   0,   0,
                              0,    0,    0,    0,    0,    0,   0,
                              0x00,                   // session_id length
                              0x00, 0x02, 0x13, 0x01, // cipher suites
                              0x01, 0x00,             // compression methods
                              0x00, 0x14,             // extensions length
                              0x00, 0x00, 0x00, 0x10, // SNI extension
                              0x00, 0x0e,             // server_name_list length
                              0x00, 0x00, 0x0b,       // host_name entry
                              'e',  'x',  'a',  'm',  'p',  'l', 'e', '.', 'c',
                              'o',  'm'};

  std::vector<uint8_t> pkt(14 + 20 + 20 + tls.size(), 0);
  pkt[12] = 0x08;
  pkt[13] = 0x00;

  const size_t ip = 14;
  pkt[ip] = 0x45;
  const uint16_t total_len = static_cast<uint16_t>(20 + 20 + tls.size());
  pkt[ip + 2] = static_cast<uint8_t>(total_len >> 8);
  pkt[ip + 3] = static_cast<uint8_t>(total_len & 0xff);
  pkt[ip + 8] = 64;
  pkt[ip + 9] = 6;
  pkt[ip + 12] = 10;
  pkt[ip + 13] = 0;
  pkt[ip + 14] = 0;
  pkt[ip + 15] = 1;
  pkt[ip + 16] = 93;
  pkt[ip + 17] = 184;
  pkt[ip + 18] = 216;
  pkt[ip + 19] = 34;

  const size_t tcp = ip + 20;
  pkt[tcp] = 0xc9;
  pkt[tcp + 1] = 0x3a;
  pkt[tcp + 2] = 0x01;
  pkt[tcp + 3] = 0xbb;
  pkt[tcp + 12] = 0x50;
  pkt[tcp + 13] = 0x18;

  std::copy(tls.begin(), tls.end(), pkt.begin() + tcp + 20);
  return pkt;
}

std::vector<uint8_t> buildIpv6QuicPacket() {
  std::vector<uint8_t> pkt(14 + 40 + 8 + 4, 0);
  pkt[12] = 0x86;
  pkt[13] = 0xdd;

  const size_t ip = 14;
  pkt[ip] = 0x60;
  const uint16_t payload_len = 8 + 4;
  pkt[ip + 4] = static_cast<uint8_t>(payload_len >> 8);
  pkt[ip + 5] = static_cast<uint8_t>(payload_len & 0xff);
  pkt[ip + 6] = 17;
  pkt[ip + 7] = 64;
  pkt[ip + 8] = 0x20;
  pkt[ip + 9] = 0x01;
  pkt[ip + 10] = 0x0d;
  pkt[ip + 11] = 0xb8;
  pkt[ip + 23] = 0x01;
  pkt[ip + 24] = 0x26;
  pkt[ip + 25] = 0x06;
  pkt[ip + 38] = 0x47;
  pkt[ip + 39] = 0x00;

  const size_t udp = ip + 40;
  pkt[udp] = 0xc3;
  pkt[udp + 1] = 0x50;
  pkt[udp + 2] = 0x01;
  pkt[udp + 3] = 0xbb;
  pkt[udp + 4] = 0x00;
  pkt[udp + 5] = 0x0c;
  pkt[udp + 8] = 0xc3;
  pkt[udp + 9] = 0x00;
  pkt[udp + 10] = 0x00;
  pkt[udp + 11] = 0x01;
  return pkt;
}

} // namespace

int main() {
  Logger::instance().enableFileOutput("netguardian_debug.log");
  Logger::instance().setLevel(LogLevel::DEBUG);

  std::atomic<int> captured_events{0};
  EventBus::instance().subscribe(EventType::PACKET_CAPTURED,
                                 [&](const Event &) { captured_events++; });

  MonitoringEngine monitor;
  monitor.start();

  SimulatedPacketSource source(10);
  source.setPacketCallback([&](std::shared_ptr<const UnifiedPacket> pkt) {
    monitor.ingestPacket(*pkt); // dereference the shared_ptr
  });

  source.start();
  std::this_thread::sleep_for(std::chrono::seconds(3));
  source.stop();
  monitor.stop();

  bool ok = true;
  if (monitor.getActiveFlows().empty()) {
    std::cout << "PIPELINE BROKEN at step N: no flows created" << std::endl;
    ok = false;
  }
  if (captured_events.load() == 0) {
    std::cout << "PIPELINE BROKEN at step N: no events captured" << std::endl;
    ok = false;
  }

  const auto tls_packet = buildTlsClientHelloPacket();
  const auto parsed_tls_ptr = PacketParserPipeline::parse(
      9999, tls_packet.data(), tls_packet.size(), 0.0);
  const auto &parsed_tls = *parsed_tls_ptr;

  if (parsed_tls.protocol != Protocol::HTTPS || !parsed_tls.has_https) {
    std::cout
        << "PIPELINE BROKEN at step N: port 443 packet was not tagged HTTPS"
        << std::endl;
    ok = false;
  }
  if (parsed_tls.tls_info.sni_hostname != "example.com") {
    std::cout << "PIPELINE BROKEN at step N: TLS SNI was not extracted"
              << std::endl;
    ok = false;
  }

  const auto quic_packet = buildIpv6QuicPacket();
  const auto parsed_quic_ptr = PacketParserPipeline::parse(
      10000, quic_packet.data(), quic_packet.size(), 0.0);
  const auto &parsed_quic = *parsed_quic_ptr;
  if (!parsed_quic.has_ipv6 || parsed_quic.protocol != Protocol::QUIC ||
      parsed_quic.dst_port != 443) {
    std::cout
        << "PIPELINE BROKEN at step N: IPv6 UDP/443 packet was not tagged QUIC"
        << std::endl;
    ok = false;
  }

  if (ok) {
    std::cout << "PIPELINE OK" << std::endl;
    return 0;
  }

  return 1;
}
