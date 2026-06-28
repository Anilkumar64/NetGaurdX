#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct NICStats
{
    uint64_t rx_bytes{0};
    uint64_t rx_packets{0};
    uint64_t rx_errors{0};
    uint64_t rx_dropped{0};
    uint64_t tx_bytes{0};
    uint64_t tx_packets{0};
    uint64_t tx_errors{0};
    uint64_t tx_dropped{0};
};

struct NICInfo
{
    std::string name;
    std::string mac_address;
    std::string ipv4_address;
    bool is_up{false};
    NICStats stats;
};

class NICModule
{
public:
    /// Returns visible interface names from /proc/net/dev, preferring up non-loopback devices.
    std::vector<std::string> listInterfaces();

    /// Read NIC counters, MAC, and IP from /proc/net/dev and /sys/class/net.
    NICInfo readStats(const std::string &interface_name);

private:
    bool interfaceIsUp(const std::string &interface_name);
    std::string readMac(const std::string &interface_name);
    std::string readIPv4(const std::string &interface_name);
};
