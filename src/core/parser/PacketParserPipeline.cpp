#include "core/parser/PacketParserPipeline.h"
#include "core/Logger.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <iomanip>
#include <memory>
#include <netinet/in.h>
#include <sstream>

// ── Public entry point ────────────────────────────────────────────────────

std::shared_ptr<const UnifiedPacket>
PacketParserPipeline::parse(uint64_t id, const uint8_t *data, size_t len,
                            double timestamp) {
  UnifiedPacket pkt{};
  pkt.id = id;
  pkt.timestamp = timestamp;
  pkt.packet_size =
      static_cast<uint32_t>(len); // BUG5-FIX: was truncating to uint16_t
  pkt.protocol = Protocol::UNKNOWN;

  if (data && len > 0) {
    pkt.raw_data.assign(data, data + len);
  }

  if (len >= 14) {
    parseEthernet(pkt);
  }

  Logger::instance().log(LogLevel::DEBUG, "PARSER",
                         "parsed proto=" + protocolToString(pkt.protocol) +
                             " src=" + pkt.src_ip + " dst=" + pkt.dst_ip);

  if (pkt.payload_len == 0) {
    pkt.raw_data.clear();
    pkt.raw_data.shrink_to_fit();
  }

  return std::make_shared<const UnifiedPacket>(std::move(pkt));
}

// ── Layer 2 — Ethernet ────────────────────────────────────────────────────

void PacketParserPipeline::parseEthernet(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  if (raw.size() < 14)
    return;

  pkt.has_eth = true;
  pkt.eth_offset = 0;
  pkt.eth_len = 14;

  std::memcpy(pkt.eth_hdr.dst, raw.data(), 6);
  std::memcpy(pkt.eth_hdr.src, raw.data() + 6, 6);
  pkt.eth_hdr.ethertype = static_cast<uint16_t>((raw[12] << 8) | raw[13]);

  uint16_t ethertype = pkt.eth_hdr.ethertype;
  size_t l3_offset = 14;
  if ((ethertype == 0x8100 || ethertype == 0x88A8) && raw.size() >= 18) {
    ethertype = static_cast<uint16_t>((raw[16] << 8) | raw[17]);
    l3_offset = 18;
    pkt.eth_len = 18;
  }

  if (ethertype == 0x0800) { // IPv4
    pkt.ip_offset = l3_offset;
    if (raw.size() >= pkt.ip_offset + 20) {
      parseIPv4(pkt);
    }
  } else if (ethertype == 0x86DD) { // IPv6
    pkt.ip_offset = l3_offset;
    if (raw.size() >= pkt.ip_offset + 40) {
      parseIPv6(pkt);
    }
  }
  // ARP
  else if (ethertype == 0x0806) {
    pkt.protocol = Protocol::ARP;
  }
}

// ── Layer 3 — IPv4 ────────────────────────────────────────────────────────

void PacketParserPipeline::parseIPv4(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t off = pkt.ip_offset;
  const uint8_t *ip_ptr = raw.data() + off;

  pkt.has_ip = true;

  pkt.ip_hdr.version_ihl = ip_ptr[0];
  pkt.ip_hdr.tos = ip_ptr[1];
  pkt.ip_hdr.total_length = static_cast<uint16_t>((ip_ptr[2] << 8) | ip_ptr[3]);
  pkt.ip_hdr.identification =
      static_cast<uint16_t>((ip_ptr[4] << 8) | ip_ptr[5]);
  pkt.ip_hdr.flags_fo = static_cast<uint16_t>((ip_ptr[6] << 8) | ip_ptr[7]);
  pkt.ip_hdr.ttl = ip_ptr[8];
  pkt.ip_hdr.protocol = ip_ptr[9];
  pkt.ip_hdr.checksum = static_cast<uint16_t>((ip_ptr[10] << 8) | ip_ptr[11]);
  std::memcpy(&pkt.ip_hdr.src_addr, ip_ptr + 12, 4);
  std::memcpy(&pkt.ip_hdr.dst_addr, ip_ptr + 16, 4);

  // IHL is lower nibble of first byte, measured in 32-bit words
  pkt.ip_len = static_cast<size_t>((pkt.ip_hdr.version_ihl & 0x0F) * 4);
  if (pkt.ip_len < 20)
    pkt.ip_len = 20; // guard against malformed packets

  // BUG4-FIX: inet_ntoa() uses a single static buffer — calling it twice races.
  // Use inet_ntop() with local buffers (same approach IPv6 parser already
  // uses).
  {
    char src_buf[INET_ADDRSTRLEN]{};
    char dst_buf[INET_ADDRSTRLEN]{};
    struct in_addr sa{}, da{};
    sa.s_addr = pkt.ip_hdr.src_addr;
    da.s_addr = pkt.ip_hdr.dst_addr;
    if (::inet_ntop(AF_INET, &sa, src_buf, sizeof(src_buf)) != nullptr)
      pkt.src_ip = src_buf;
    if (::inet_ntop(AF_INET, &da, dst_buf, sizeof(dst_buf)) != nullptr)
      pkt.dst_ip = dst_buf;
  }

  pkt.transport_offset = pkt.ip_offset + pkt.ip_len;

  const uint8_t ip_proto = pkt.ip_hdr.protocol;
  if (ip_proto == 6 && raw.size() >= pkt.transport_offset + 20)
    parseTCP(pkt);
  else if (ip_proto == 17 && raw.size() >= pkt.transport_offset + 8)
    parseUDP(pkt);
  else if (ip_proto == 1 && raw.size() >= pkt.transport_offset + 8)
    parseICMP(pkt);
}

// ── Layer 3 — IPv6 ────────────────────────────────────────────────────────

void PacketParserPipeline::parseIPv6(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t off = pkt.ip_offset;
  const uint8_t *ip_ptr = raw.data() + off;

  pkt.has_ip = true;
  pkt.has_ipv6 = true;

  pkt.ipv6_hdr.version_traffic_flow = (static_cast<uint32_t>(ip_ptr[0]) << 24) |
                                      (static_cast<uint32_t>(ip_ptr[1]) << 16) |
                                      (static_cast<uint32_t>(ip_ptr[2]) << 8) |
                                      static_cast<uint32_t>(ip_ptr[3]);
  pkt.ipv6_hdr.payload_length =
      static_cast<uint16_t>((ip_ptr[4] << 8) | ip_ptr[5]);
  pkt.ipv6_hdr.next_header = ip_ptr[6];
  pkt.ipv6_hdr.hop_limit = ip_ptr[7];
  std::memcpy(pkt.ipv6_hdr.src_addr, ip_ptr + 8, 16);
  std::memcpy(pkt.ipv6_hdr.dst_addr, ip_ptr + 24, 16);

  char src_buf[INET6_ADDRSTRLEN] = {};
  char dst_buf[INET6_ADDRSTRLEN] = {};
  if (::inet_ntop(AF_INET6, pkt.ipv6_hdr.src_addr, src_buf, sizeof(src_buf)) !=
      nullptr) {
    pkt.src_ip = src_buf;
  }
  if (::inet_ntop(AF_INET6, pkt.ipv6_hdr.dst_addr, dst_buf, sizeof(dst_buf)) !=
      nullptr) {
    pkt.dst_ip = dst_buf;
  }

  pkt.ip_len = 40;
  pkt.transport_offset = pkt.ip_offset + pkt.ip_len;

  const uint8_t next = pkt.ipv6_hdr.next_header;
  if (next == 6 && raw.size() >= pkt.transport_offset + 20)
    parseTCP(pkt);
  else if (next == 17 && raw.size() >= pkt.transport_offset + 8)
    parseUDP(pkt);
  else if (next == 58 && raw.size() >= pkt.transport_offset + 8)
    parseICMP(pkt);
}

// ── Layer 4 — TCP ─────────────────────────────────────────────────────────

void PacketParserPipeline::parseTCP(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t off = pkt.transport_offset;
  const uint8_t *t = raw.data() + off;

  pkt.has_tcp = true;
  pkt.protocol = Protocol::TCP;

  pkt.tcp_hdr.src_port = static_cast<uint16_t>((t[0] << 8) | t[1]);
  pkt.tcp_hdr.dst_port = static_cast<uint16_t>((t[2] << 8) | t[3]);
  pkt.tcp_hdr.seq_num =
      static_cast<uint32_t>((t[4] << 24) | (t[5] << 16) | (t[6] << 8) | t[7]);
  pkt.tcp_hdr.ack_num =
      static_cast<uint32_t>((t[8] << 24) | (t[9] << 16) | (t[10] << 8) | t[11]);
  pkt.tcp_hdr.data_offset_res = t[12];
  pkt.tcp_hdr.flags = t[13];
  pkt.tcp_hdr.window = static_cast<uint16_t>((t[14] << 8) | t[15]);
  pkt.tcp_hdr.checksum = static_cast<uint16_t>((t[16] << 8) | t[17]);
  pkt.tcp_hdr.urg_ptr = static_cast<uint16_t>((t[18] << 8) | t[19]);

  pkt.src_port = pkt.tcp_hdr.src_port;
  pkt.dst_port = pkt.tcp_hdr.dst_port;
  pkt.seq_num = pkt.tcp_hdr.seq_num;
  pkt.ack_num = pkt.tcp_hdr.ack_num;
  pkt.tcp_flags = pkt.tcp_hdr.flags;

  // Data offset (in 32-bit words) is the high nibble of byte 12
  size_t tcp_hdr_len =
      static_cast<size_t>((pkt.tcp_hdr.data_offset_res >> 4) & 0xF) * 4;
  if (tcp_hdr_len < 20)
    tcp_hdr_len = 20;

  pkt.transport_len = tcp_hdr_len;
  pkt.payload_offset = pkt.transport_offset + tcp_hdr_len;
  pkt.payload_len =
      (raw.size() > pkt.payload_offset) ? raw.size() - pkt.payload_offset : 0;

  const uint16_t sp = pkt.src_port, dp = pkt.dst_port;
  if (dp == 443 || sp == 443) {
    pkt.has_https = true;
    pkt.protocol = Protocol::HTTPS;
    if (pkt.payload_len > 0) {
      parseTLS(pkt);
    }
  }
  // Try HTTP on port 80 / 8080
  else if (pkt.payload_len > 0) {
    if (dp == 80 || dp == 8080 || sp == 80 || sp == 8080) {
      parseHTTP(pkt);
    }
  }
}

// ── Layer 4 — UDP ─────────────────────────────────────────────────────────

void PacketParserPipeline::parseUDP(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t off = pkt.transport_offset;
  const uint8_t *t = raw.data() + off;

  pkt.has_udp = true;
  pkt.protocol = Protocol::UDP;

  pkt.udp_hdr.src_port = static_cast<uint16_t>((t[0] << 8) | t[1]);
  pkt.udp_hdr.dst_port = static_cast<uint16_t>((t[2] << 8) | t[3]);
  pkt.udp_hdr.length = static_cast<uint16_t>((t[4] << 8) | t[5]);
  pkt.udp_hdr.checksum = static_cast<uint16_t>((t[6] << 8) | t[7]);

  pkt.src_port = pkt.udp_hdr.src_port;
  pkt.dst_port = pkt.udp_hdr.dst_port;

  pkt.transport_len = 8;
  pkt.payload_offset = pkt.transport_offset + 8;
  pkt.payload_len =
      (raw.size() > pkt.payload_offset) ? raw.size() - pkt.payload_offset : 0;

  if (pkt.payload_len >= 12) {
    uint16_t sp = pkt.src_port, dp = pkt.dst_port;
    if (dp == 53 || sp == 53 || dp == 5353 || sp == 5353) {
      parseDNS(pkt);
    }
  }
  if (pkt.protocol == Protocol::UDP &&
      (pkt.src_port == 443 || pkt.dst_port == 443)) {
    pkt.protocol = Protocol::QUIC;
    pkt.has_https = true;
  }
}

// ── Layer 4 — ICMP ────────────────────────────────────────────────────────

void PacketParserPipeline::parseICMP(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t off = pkt.transport_offset;
  const uint8_t *t = raw.data() + off;

  pkt.has_icmp = true;
  pkt.protocol = Protocol::ICMP;

  pkt.icmp_hdr.type = t[0];
  pkt.icmp_hdr.code = t[1];
  pkt.icmp_hdr.checksum = static_cast<uint16_t>((t[2] << 8) | t[3]);
  std::memcpy(&pkt.icmp_hdr.rest, t + 4, 4);

  pkt.transport_len = 8;
  pkt.payload_offset = pkt.transport_offset + 8;
  pkt.payload_len =
      (raw.size() > pkt.payload_offset) ? raw.size() - pkt.payload_offset : 0;
}

// ── Layer 7 — HTTP ────────────────────────────────────────────────────────

void PacketParserPipeline::parseHTTP(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t pay_off = pkt.payload_offset;
  const size_t pay_len = pkt.payload_len;
  if (pay_len < 4)
    return;

  const char *p = reinterpret_cast<const char *>(raw.data() + pay_off);
  std::string head(p, std::min(pay_len, (size_t)256));

  // Detect HTTP request
  if (head.compare(0, 3, "GET") == 0 || head.compare(0, 4, "POST") == 0 ||
      head.compare(0, 3, "PUT") == 0 || head.compare(0, 6, "DELETE") == 0 ||
      head.compare(0, 4, "HEAD") == 0 || head.compare(0, 7, "OPTIONS") == 0) {

    pkt.has_http = true;
    pkt.protocol = Protocol::HTTP;

    // Extract method
    size_t sp1 = head.find(' ');
    if (sp1 != std::string::npos) {
      pkt.http_info.method = head.substr(0, sp1);
      size_t sp2 = head.find(' ', sp1 + 1);
      if (sp2 != std::string::npos) {
        pkt.http_info.url = head.substr(sp1 + 1, sp2 - sp1 - 1);
        size_t nl = head.find('\r', sp2);
        pkt.http_info.version =
            head.substr(sp2 + 1, (nl != std::string::npos) ? nl - sp2 - 1 : 8);
      }
    }
    pkt.http_info.body_preview = head.substr(0, std::min((size_t)64, pay_len));
  }
  // Detect HTTP response
  else if (head.compare(0, 4, "HTTP") == 0) {
    pkt.has_http = true;
    pkt.protocol = Protocol::HTTP;
    // "HTTP/1.1 200 OK"
    size_t sp1 = head.find(' ');
    if (sp1 != std::string::npos) {
      size_t sp2 = head.find(' ', sp1 + 1);
      pkt.http_info.version = head.substr(0, sp1);
      pkt.http_info.status_code =
          head.substr(sp1 + 1, (sp2 != std::string::npos) ? sp2 - sp1 - 1 : 3);
    }
    pkt.http_info.body_preview = head.substr(0, std::min((size_t)64, pay_len));
  }
}

// ── Layer 7 — TLS ────────────────────────────────────────────────────────

void PacketParserPipeline::parseTLS(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t pay_off = pkt.payload_offset;
  const size_t pay_len = pkt.payload_len;
  if (pay_len < 5)
    return;

  const uint8_t *tls = raw.data() + pay_off;
  const uint8_t content_type = tls[0];
  const size_t record_len = static_cast<size_t>((tls[3] << 8) | tls[4]);
  if (content_type != 0x16 || record_len + 5 > pay_len)
    return;

  size_t pos = 5;
  if (pos + 4 > pay_len || tls[pos] != 0x01)
    return;

  const size_t handshake_len = (static_cast<size_t>(tls[pos + 1]) << 16) |
                               (static_cast<size_t>(tls[pos + 2]) << 8) |
                               static_cast<size_t>(tls[pos + 3]);
  pos += 4;

  const size_t handshake_end = std::min(pay_len, pos + handshake_len);
  if (pos + 34 > handshake_end)
    return;

  pos += 2;  // ClientHello legacy_version
  pos += 32; // random

  if (pos + 1 > handshake_end)
    return;
  const size_t session_id_len = tls[pos++];
  if (pos + session_id_len + 2 > handshake_end)
    return;
  pos += session_id_len;

  const size_t cipher_suites_len =
      static_cast<size_t>((tls[pos] << 8) | tls[pos + 1]);
  pos += 2;
  if (pos + cipher_suites_len + 1 > handshake_end)
    return;
  pos += cipher_suites_len;

  const size_t compression_methods_len = tls[pos++];
  if (pos + compression_methods_len + 2 > handshake_end)
    return;
  pos += compression_methods_len;

  const size_t extensions_len =
      static_cast<size_t>((tls[pos] << 8) | tls[pos + 1]);
  pos += 2;
  const size_t extensions_end = std::min(handshake_end, pos + extensions_len);

  while (pos + 4 <= extensions_end) {
    const uint16_t ext_type =
        static_cast<uint16_t>((tls[pos] << 8) | tls[pos + 1]);
    const size_t ext_len =
        static_cast<size_t>((tls[pos + 2] << 8) | tls[pos + 3]);
    pos += 4;
    if (pos + ext_len > extensions_end)
      return;

    if (ext_type == 0x0000 && ext_len >= 2) {
      size_t sni_pos = pos;
      const size_t server_name_list_len =
          static_cast<size_t>((tls[sni_pos] << 8) | tls[sni_pos + 1]);
      sni_pos += 2;
      const size_t server_name_list_end =
          std::min(pos + ext_len, sni_pos + server_name_list_len);

      while (sni_pos + 3 <= server_name_list_end) {
        const uint8_t name_type = tls[sni_pos++];
        const size_t name_len =
            static_cast<size_t>((tls[sni_pos] << 8) | tls[sni_pos + 1]);
        sni_pos += 2;
        if (sni_pos + name_len > server_name_list_end)
          return;

        if (name_type == 0 && name_len > 0) {
          pkt.tls_info.sni_hostname.assign(
              reinterpret_cast<const char *>(tls + sni_pos), name_len);
          return;
        }
        sni_pos += name_len;
      }
    }

    pos += ext_len;
  }
}

// ── Layer 7 — DNS ────────────────────────────────────────────────────────

void PacketParserPipeline::parseDNS(UnifiedPacket &pkt) {
  const auto &raw = pkt.raw_data;
  const size_t pay_off = pkt.payload_offset;
  const size_t pay_len = pkt.payload_len;
  if (pay_len < 12)
    return;

  const uint8_t *dns = raw.data() + pay_off;

  pkt.has_dns = true;
  pkt.protocol = Protocol::DNS;

  pkt.dns_hdr.id = static_cast<uint16_t>((dns[0] << 8) | dns[1]);
  pkt.dns_hdr.flags = static_cast<uint16_t>((dns[2] << 8) | dns[3]);
  pkt.dns_hdr.qdcount = static_cast<uint16_t>((dns[4] << 8) | dns[5]);
  pkt.dns_hdr.ancount = static_cast<uint16_t>((dns[6] << 8) | dns[7]);
  pkt.dns_hdr.nscount = static_cast<uint16_t>((dns[8] << 8) | dns[9]);
  pkt.dns_hdr.arcount = static_cast<uint16_t>((dns[10] << 8) | dns[11]);
  pkt.dns_info.query_name.clear();
  pkt.dns_info.answers.clear();

  bool is_resp = (pkt.dns_hdr.flags & 0x8000) != 0;

  // Walk past the 12-byte header
  size_t pos = 12;

  // ── Parse first question QNAME ────────────────────────────────────────
  if (pkt.dns_hdr.qdcount > 0 && pos < pay_len) {
    std::string name;
    while (pos < pay_len) {
      uint8_t label_len = dns[pos++];
      if (label_len == 0)
        break;
      if ((label_len & 0xC0) == 0xC0) {
        pos++;
        break;
      } // pointer
      if (pos + label_len > pay_len)
        break;
      if (!name.empty())
        name += '.';
      name.append(reinterpret_cast<const char *>(dns + pos), label_len);
      pos += label_len;
    }
    pkt.dns_info.query_name = name;
    if (pos + 4 <= pay_len)
      pos += 4; // QTYPE + QCLASS
  }

  // ── Parse answer RRs (A records only) if this is a response ──────────
  if (is_resp && pkt.dns_hdr.ancount > 0) {
    for (uint16_t i = 0; i < pkt.dns_hdr.ancount && pos + 10 < pay_len; ++i) {
      // Skip NAME field (may be a pointer)
      if ((dns[pos] & 0xC0) == 0xC0)
        pos += 2;
      else {
        while (pos < pay_len && dns[pos] != 0)
          pos++;
        pos++;
      }
      if (pos + 10 > pay_len)
        break;

      uint16_t type = static_cast<uint16_t>((dns[pos] << 8) | dns[pos + 1]);
      // uint16_t cls = …  (skip)
      // uint32_t ttl = …  (skip)
      uint16_t rdlen =
          static_cast<uint16_t>((dns[pos + 8] << 8) | dns[pos + 9]);
      pos += 10;

      if (type == 1 && rdlen == 4 &&
          pos + 4 <=
              pay_len) { // A record — BUG4-FIX: use inet_ntop not inet_ntoa
        struct in_addr addr{};
        std::memcpy(&addr.s_addr, dns + pos, 4);
        char abuf[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &addr, abuf, sizeof(abuf)) != nullptr)
          pkt.dns_info.answers.push_back(abuf);
      }
      pos += rdlen;
    }
  }
}
