#include "core/capture/SimulatedPacketSource.h"
#include "core/eventbus/EventBus.h"
#include "core/Logger.h"
#include "core/parser/PacketParserPipeline.h"
#include <chrono>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm>
#include <cstddef>

// ── IP pairs used in simulation ───────────────────────────────────────────
static const std::pair<const char *, const char *> kIPPairs[] = {
    {"192.168.1.100", "93.184.216.34"},  // HTTP to example.com
    {"10.0.0.5",      "8.8.8.8"},        // DNS to Google
    {"172.16.0.1",    "192.168.1.1"},    // LAN ICMP
    {"192.168.1.200", "151.101.1.140"},  // HTTPS to fastly
    {"192.168.10.44", "1.1.1.1"},        // Alternate resolver
};
static constexpr int kNumPairs = 5;

static double nowSeconds()
{
    return std::chrono::duration<double>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// ── Ctor / dtor ───────────────────────────────────────────────────────────

// Default to 5 PPS — slow enough to read, fast enough to feel live
SimulatedPacketSource::SimulatedPacketSource(int pps) : pps_(pps > 0 ? pps : 5) {}

SimulatedPacketSource::~SimulatedPacketSource() { stop(); }

void SimulatedPacketSource::setPacketCallback(std::function<void(std::shared_ptr<const UnifiedPacket>)> cb)
{
    callback_ = std::move(cb);
}

void SimulatedPacketSource::start()
{
    if (running_.load())
        return;
    running_ = true;
    thread_ = std::thread(&SimulatedPacketSource::generateLoop, this);
}

void SimulatedPacketSource::stop()
{
    running_ = false;
    if (thread_.joinable())
        thread_.join();
}

// ── Internal deliver helper ───────────────────────────────────────────────

void SimulatedPacketSource::deliver(UnifiedPacket pkt)
{
    // BUG1-FIX: parse() now returns shared_ptr — single allocation shared everywhere
    auto parsed_ptr = PacketParserPipeline::parse(
        pkt.id,
        pkt.raw_data.data(),
        pkt.raw_data.size(),
        pkt.timestamp);

    // Attach flow metadata that the simulated source knows about.
    // We need a mutable copy only for these two fields; do it before freezing.
    UnifiedPacket mutable_pkt = *parsed_ptr;
    mutable_pkt.flow_id   = pkt.flow_id;
    mutable_pkt.direction = pkt.direction;
    auto shared_pkt = std::make_shared<const UnifiedPacket>(std::move(mutable_pkt));

    Logger::instance().log(LogLevel::DEBUG, "CAPTURE",
        "delivering id=" + std::to_string(shared_pkt->id) +
        " proto=" + protocolToString(shared_pkt->protocol));

    if (callback_)
        callback_(shared_pkt);

    EventBus::instance().publish({EventType::PACKET_CAPTURED,
                                  shared_pkt->timestamp,
                                  "Simulated packet",
                                  "L2",
                                  "INFO",
                                  shared_pkt});
}

// ── Raw-byte builder ─────────────────────────────────────────────────────

void SimulatedPacketSource::fillRawBytes(UnifiedPacket &pkt)
{
    std::vector<uint8_t> frame;
    frame.reserve(256);

    auto push2 = [&](uint16_t v) {
        frame.push_back(static_cast<uint8_t>(v >> 8));
        frame.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    auto push4 = [&](uint32_t v) {
        frame.push_back(static_cast<uint8_t>(v >> 24));
        frame.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        frame.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    auto appendDnsName = [&](const std::string& name) {
        size_t start = 0;
        while (start < name.size()) {
            size_t dot = name.find('.', start);
            size_t end = (dot == std::string::npos) ? name.size() : dot;
            size_t len = end - start;
            frame.push_back(static_cast<uint8_t>(std::min<size_t>(len, 63)));
            frame.insert(frame.end(), name.begin() + (std::ptrdiff_t)start,
                         name.begin() + (std::ptrdiff_t)end);
            if (dot == std::string::npos) break;
            start = dot + 1;
        }
        frame.push_back(0x00);
    };

    // Ethernet header
    for (int i = 0; i < 6; ++i) frame.push_back(0xFF);          // dst MAC (broadcast)
    for (int i = 0; i < 6; ++i) frame.push_back((uint8_t)(i+1));// src MAC
    frame.push_back(0x08); frame.push_back(0x00);                // IPv4

    pkt.eth_offset = 0;
    pkt.eth_len    = 14;
    pkt.has_eth    = true;

    // IPv4 header
    size_t ip_start = frame.size();
    frame.push_back(0x45); frame.push_back(0x00);
    frame.push_back(0x00); frame.push_back(0x00); // total length — back-filled
    frame.push_back(0xAB); frame.push_back(0xCD); // ID
    frame.push_back(0x40); frame.push_back(0x00); // flags/fragment
    frame.push_back(64);                           // TTL

    uint8_t ip_proto = pkt.has_tcp ? 6 : pkt.has_udp ? 17 : 1;
    frame.push_back(ip_proto);
    frame.push_back(0x00); frame.push_back(0x00); // checksum

    struct in_addr sa{};
    ::inet_pton(AF_INET, pkt.src_ip.c_str(), &sa);
    uint8_t *sp = reinterpret_cast<uint8_t *>(&sa.s_addr);
    frame.insert(frame.end(), sp, sp + 4);

    struct in_addr da{};
    ::inet_pton(AF_INET, pkt.dst_ip.c_str(), &da);
    uint8_t *dp = reinterpret_cast<uint8_t *>(&da.s_addr);
    frame.insert(frame.end(), dp, dp + 4);

    pkt.ip_offset = ip_start;
    pkt.ip_len    = 20;
    pkt.has_ip    = true;

    size_t transport_start = frame.size();
    pkt.transport_offset   = transport_start;

    if (pkt.has_tcp) {
        push2(pkt.src_port); push2(pkt.dst_port);
        push4(pkt.seq_num);  push4(pkt.ack_num);
        frame.push_back(0x50);          // data offset=5
        frame.push_back(pkt.tcp_flags);
        push2(65535); push2(0); push2(0);
        pkt.transport_len = 20;
    } else if (pkt.has_udp) {
        push2(pkt.src_port); push2(pkt.dst_port);
        frame.push_back(0x00); frame.push_back(0x00); // length — back-filled
        frame.push_back(0x00); frame.push_back(0x00); // checksum
        pkt.transport_len = 8;
    } else if (pkt.has_icmp) {
        frame.push_back(8); frame.push_back(0);       // type/code
        frame.push_back(0); frame.push_back(0);       // checksum
        frame.push_back(0); frame.push_back(1);       // identifier
        frame.push_back(0); frame.push_back(1);       // sequence
        pkt.transport_len = 8;
    }

    // Payload
    pkt.payload_offset = frame.size();
    if (pkt.has_http) {
        std::string body = !pkt.http_info.method.empty()
            ? pkt.http_info.method + " " + pkt.http_info.url + " HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetGuardianX\r\n\r\n"
            : "HTTP/1.1 " + pkt.http_info.status_code + " OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
        frame.insert(frame.end(), body.begin(), body.end());
    } else if (pkt.has_dns) {
        const bool response = !pkt.dns_info.answers.empty();
        push2(0x1234);
        push2(response ? 0x8180 : 0x0100);
        push2(0x0001); push2(response ? 0x0001 : 0x0000);
        push2(0x0000); push2(0x0000);
        appendDnsName(pkt.dns_info.query_name.empty() ? "example.com" : pkt.dns_info.query_name);
        push2(0x0001); push2(0x0001);
        if (response) {
            frame.push_back(0xC0); frame.push_back(0x0C);
            push2(0x0001); push2(0x0001);
            push4(60); push2(0x0004);
            struct in_addr ans{};
            ::inet_pton(AF_INET, pkt.dns_info.answers.front().c_str(), &ans);
            uint8_t *ap = reinterpret_cast<uint8_t *>(&ans.s_addr);
            frame.insert(frame.end(), ap, ap + 4);
        }
    }

    pkt.payload_len = frame.size() - pkt.payload_offset;

    if (pkt.has_udp) {
        uint16_t udp_len = (uint16_t)(pkt.transport_len + pkt.payload_len);
        frame[transport_start + 4] = (uint8_t)(udp_len >> 8);
        frame[transport_start + 5] = (uint8_t)(udp_len & 0xFF);
    }

    uint16_t ip_total = (uint16_t)(frame.size() - ip_start);
    frame[ip_start + 2] = (uint8_t)(ip_total >> 8);
    frame[ip_start + 3] = (uint8_t)(ip_total & 0xFF);

    pkt.raw_data    = std::move(frame);
    pkt.packet_size = (uint16_t)pkt.raw_data.size();
    pkt.timestamp   = nowSeconds();
}

// ── Packet factories ──────────────────────────────────────────────────────

UnifiedPacket SimulatedPacketSource::makeTCPSyn(const std::string &src, const std::string &dst,
                                                uint16_t sport, uint16_t dport, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::TCP; p.has_tcp = true;
    p.src_ip = src; p.dst_ip = dst; p.src_port = sport; p.dst_port = dport;
    p.tcp_flags = 0x02; p.seq_num = 1000 + (next_id_ & 0xFFFF); p.ack_num = 0;
    p.flow_id = flow_id; fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeTCPSynAck(const std::string &src, const std::string &dst,
                                                    uint16_t sport, uint16_t dport, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::TCP; p.has_tcp = true;
    p.src_ip = src; p.dst_ip = dst; p.src_port = sport; p.dst_port = dport;
    p.tcp_flags = 0x12; p.seq_num = 5000; p.ack_num = 1001 + (next_id_ & 0xFFFF);
    p.flow_id = flow_id; fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeTCPAck(const std::string &src, const std::string &dst,
                                                 uint16_t sport, uint16_t dport, uint32_t seq, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::TCP; p.has_tcp = true;
    p.src_ip = src; p.dst_ip = dst; p.src_port = sport; p.dst_port = dport;
    p.tcp_flags = 0x10; p.seq_num = seq; p.ack_num = 5001;
    p.flow_id = flow_id; fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeHTTPGet(const std::string &src, const std::string &dst, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::HTTP; p.has_tcp = true; p.has_http = true;
    p.src_ip = src; p.dst_ip = dst;
    p.src_port = (uint16_t)(40000 + (flow_id % 10000)); p.dst_port = 80;
    p.tcp_flags = 0x18; p.seq_num = 1001; p.ack_num = 5001; p.flow_id = flow_id;
    p.http_info.method = "GET"; p.http_info.url = "/index.html"; p.http_info.version = "HTTP/1.1";
    fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeHTTPResponse(const std::string &src, const std::string &dst, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::HTTP; p.has_tcp = true; p.has_http = true;
    p.src_ip = src; p.dst_ip = dst;
    p.src_port = 80; p.dst_port = (uint16_t)(40000 + (flow_id % 10000));
    p.tcp_flags = 0x18; p.seq_num = 5001; p.ack_num = 1200; p.flow_id = flow_id;
    p.http_info.version = "HTTP/1.1"; p.http_info.status_code = "200";
    p.http_info.body_preview = "Hello, World!";
    fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeDNSQuery(const std::string &src, const std::string &dst,
                                                   const std::string &name, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::DNS; p.has_udp = true; p.has_dns = true;
    p.src_ip = src; p.dst_ip = dst;
    p.src_port = (uint16_t)(50000 + (flow_id % 5000)); p.dst_port = 53; p.flow_id = flow_id;
    p.dns_info.query_name = name; fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeDNSResponse(const std::string &src, const std::string &dst,
                                                      const std::string &name, const std::string &answer,
                                                      uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::DNS; p.has_udp = true; p.has_dns = true;
    p.src_ip = src; p.dst_ip = dst;
    p.src_port = 53; p.dst_port = (uint16_t)(50000 + (flow_id % 5000)); p.flow_id = flow_id;
    p.dns_info.query_name = name; p.dns_info.answers.push_back(answer);
    fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeICMPEcho(const std::string &src, const std::string &dst, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::ICMP; p.has_icmp = true;
    p.src_ip = src; p.dst_ip = dst; p.flow_id = flow_id;
    p.icmp_hdr.type = 8; p.icmp_hdr.code = 0; fillRawBytes(p); return p;
}

UnifiedPacket SimulatedPacketSource::makeTCPRst(const std::string &src, const std::string &dst, uint32_t flow_id)
{
    UnifiedPacket p{};
    p.id = next_id_++; p.protocol = Protocol::TCP; p.has_tcp = true;
    p.src_ip = src; p.dst_ip = dst;
    p.src_port = (uint16_t)(40000 + (flow_id % 10000)); p.dst_port = 80;
    p.tcp_flags = 0x04; p.seq_num = 9999; p.flow_id = flow_id;
    fillRawBytes(p); return p;
}

// ── Main generation loop ──────────────────────────────────────────────────
// Produces a realistic mix at ~5 PPS by default (configurable).
// Sequence per "scenario" cycle (20 iterations):
//  1-3  : TCP handshake (SYN → SYN-ACK → ACK)
//  4-5  : HTTP GET + 200 response
//  6-7  : DNS query + response
//  8-9  : ICMP echo (ping)
//  10   : DNS query (another host)
//  11-13: TCP data exchange
//  14   : TCP RST (simulates connection refused)
//  15-17: DNS query + response (different resolver)
//  18-19: HTTP GET to different host
//  20   : ICMP echo

void SimulatedPacketSource::generateLoop()
{
    // Inter-packet gap — e.g. 5 PPS → 200ms between packets
    const auto gap = std::chrono::milliseconds(1000 / pps_);
    int counter    = 0;
    uint32_t fid   = 1;

    static const struct { const char *host; const char *name; } kDnsHosts[] = {
        {"example.com",     "93.184.216.34"},
        {"google.com",      "142.250.80.46"},
        {"github.com",      "140.82.112.4"},
        {"cloudflare.com",  "104.16.133.229"},
    };
    int dnsIdx = 0;

    while (running_.load())
    {
        std::this_thread::sleep_for(gap);
        if (!running_.load()) break;

        counter = (counter % 20) + 1;
        const auto &pair = kIPPairs[counter % kNumPairs];
        const std::string &host = pair.first;
        const std::string &peer = pair.second;

        switch (counter)
        {
        // ── TCP three-way handshake ──────────────────────────────────────────
        case 1: {
            uint16_t sport = (uint16_t)(30000 + (fid % 10000));
            deliver(makeTCPSyn(host, peer, sport, 80, fid));
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
            deliver(makeTCPSynAck(peer, host, 80, sport, fid));
            std::this_thread::sleep_for(std::chrono::milliseconds(40));
            deliver(makeTCPAck(host, peer, sport, 80, 1001, fid++));
            break;
        }
        // ── HTTP request/response ────────────────────────────────────────────
        case 4:
            deliver(makeHTTPGet(host, peer, fid));
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
            deliver(makeHTTPResponse(peer, host, fid++));
            break;

        // ── DNS exchange ─────────────────────────────────────────────────────
        case 6: {
            auto &d = kDnsHosts[dnsIdx % 4];
            deliver(makeDNSQuery(host, peer, d.host, fid));
            std::this_thread::sleep_for(std::chrono::milliseconds(60));
            deliver(makeDNSResponse(peer, host, d.host, d.name, fid++));
            dnsIdx++;
            break;
        }
        // ── ICMP ping ────────────────────────────────────────────────────────
        case 8:
        case 20:
            deliver(makeICMPEcho(host, peer, fid++));
            break;

        // ── Another DNS ──────────────────────────────────────────────────────
        case 10: {
            auto &d = kDnsHosts[(dnsIdx + 2) % 4];
            deliver(makeDNSQuery(host, "1.1.1.1", d.host, fid));
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            deliver(makeDNSResponse("1.1.1.1", host, d.host, d.name, fid++));
            break;
        }
        // ── TCP data segments ─────────────────────────────────────────────────
        case 11:
        case 12:
        case 13: {
            uint16_t sport = (uint16_t)(40000 + (fid % 10000));
            deliver(makeTCPAck(host, peer, sport, 443, (uint32_t)(counter * 1000), fid++));
            break;
        }
        // ── TCP RST ──────────────────────────────────────────────────────────
        case 14:
            deliver(makeTCPRst(peer, host, fid++));
            break;

        // ── HTTP to different host ────────────────────────────────────────────
        case 18: {
            const auto &p2 = kIPPairs[(counter + 2) % kNumPairs];
            deliver(makeHTTPGet(p2.first, p2.second, fid));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            deliver(makeHTTPResponse(p2.second, p2.first, fid++));
            break;
        }
        default:
            // Remaining slots: plain ICMP or TCP ACK to fill gaps
            if (counter % 2 == 0)
                deliver(makeICMPEcho(host, peer, fid++));
            else {
                uint16_t sport = (uint16_t)(35000 + (fid % 5000));
                deliver(makeTCPAck(host, peer, sport, 80, counter * 100, fid++));
            }
            break;
        }
    }
}
