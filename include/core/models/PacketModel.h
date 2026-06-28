#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <any>

// ── Wire-format header structs (packed so we can memcpy directly) ─────────

#pragma pack(push, 1)
struct EthernetHeader
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype; // host-byte-order after parse
};

struct IPv4Header
{
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fo;
    uint8_t ttl;
    uint8_t protocol; // 1=ICMP 6=TCP 17=UDP
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct IPv6Header
{
    uint32_t version_traffic_flow;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
};

struct TCPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_res; // high nibble = data offset (×4)
    uint8_t flags;           // 0x02=SYN 0x10=ACK 0x01=FIN 0x04=RST 0x08=PSH
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};

struct UDPHeader
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct ICMPHeader
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
};

struct DNSHeader
{
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

// ── Application-layer decoded info ───────────────────────────────────────

struct HTTPInfo
{
    std::string method; // GET / POST / PUT / …
    std::string url;
    std::string version;      // HTTP/1.1
    std::string status_code;  // "200" / "404" / …
    std::string body_preview; // first 64 bytes of body
};

struct DNSInfo
{
    std::string query_name;
    std::vector<std::string> answers; // resolved A / AAAA addresses
};

struct TLSInfo
{
    std::string sni_hostname;
};

// ── Enums ─────────────────────────────────────────────────────────────────

enum class Protocol
{
    UNKNOWN,
    ARP,
    ICMP,
    TCP,
    UDP,
    DNS,
    HTTP,
    HTTPS,
    TLS,
    QUIC
};
enum class Direction
{
    TX,
    RX,
    UNKNOWN
};

// ── Free functions ────────────────────────────────────────────────────────

std::string protocolToString(Protocol p);
std::string tcpFlagsToString(uint8_t flags);

// ── Master packet struct ──────────────────────────────────────────────────

struct UnifiedPacket
{
    uint64_t id{0};
    double timestamp{0.0};
    Direction direction{Direction::UNKNOWN};
    Protocol protocol{Protocol::UNKNOWN};

    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint32_t seq_num{0};
    uint32_t ack_num{0};
    uint8_t tcp_flags{0};
    uint32_t packet_size{0};  // BUG5-FIX: was uint16_t, silently capped 350KB packets at 65535
    uint32_t flow_id{0};

    std::vector<uint8_t> raw_data;

    // Layer offsets and lengths within raw_data
    size_t eth_offset{0};
    size_t ip_offset{0};
    size_t transport_offset{0};
    size_t payload_offset{0};
    size_t eth_len{0};
    size_t ip_len{0};
    size_t transport_len{0};
    size_t payload_len{0};

    // Decoded headers
    EthernetHeader eth_hdr{};
    IPv4Header ip_hdr{};
    IPv6Header ipv6_hdr{};
    TCPHeader tcp_hdr{};
    UDPHeader udp_hdr{};
    ICMPHeader icmp_hdr{};
    DNSHeader dns_hdr{};
    HTTPInfo http_info{};
    DNSInfo dns_info{};
    TLSInfo tls_info{};

    // Presence flags
    bool has_eth{false};
    bool has_ip{false};
    bool has_ipv6{false};
    bool has_tcp{false};
    bool has_udp{false};
    bool has_icmp{false};
    bool has_http{false};
    bool has_https{false};
    bool has_dns{false};
};
