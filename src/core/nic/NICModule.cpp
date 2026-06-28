#include "core/nic/NICModule.h"
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>

std::vector<std::string> NICModule::listInterfaces()
{
    std::vector<std::string> up_ifaces;
    std::vector<std::string> down_ifaces;
    std::vector<std::string> loopback_ifaces;
    std::ifstream f("/proc/net/dev");
    if (!f.is_open()) return {"lo"};

    std::string line;
    std::getline(f, line); // header 1
    std::getline(f, line); // header 2
    while (std::getline(f, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string name = line.substr(0, pos);
        // trim whitespace
        name.erase(0, name.find_first_not_of(" \t"));
        name.erase(name.find_last_not_of(" \t") + 1);
        if (name.empty()) {
            continue;
        }
        if (name == "lo") {
            loopback_ifaces.push_back(name);
        } else if (interfaceIsUp(name)) {
            up_ifaces.push_back(name);
        } else {
            down_ifaces.push_back(name);
        }
    }

    std::vector<std::string> ifaces;
    ifaces.insert(ifaces.end(), up_ifaces.begin(), up_ifaces.end());
    ifaces.insert(ifaces.end(), down_ifaces.begin(), down_ifaces.end());
    ifaces.insert(ifaces.end(), loopback_ifaces.begin(), loopback_ifaces.end());
    if (ifaces.empty()) ifaces.push_back("lo");
    return ifaces;
}

std::string NICModule::readMac(const std::string& iface)
{
    std::ifstream f("/sys/class/net/" + iface + "/address");
    if (!f.is_open()) return "00:00:00:00:00:00";
    std::string mac;
    std::getline(f, mac);
    return mac.empty() ? "00:00:00:00:00:00" : mac;
}

std::string NICModule::readIPv4(const std::string& iface)
{
    struct ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) != 0) {
        return "N/A";
    }

    std::string result = "N/A";
    for (struct ifaddrs* it = addrs; it != nullptr; it = it->ifa_next) {
        if (it->ifa_addr == nullptr || iface != it->ifa_name ||
            it->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        char buf[INET_ADDRSTRLEN] = {};
        auto* addr = reinterpret_cast<struct sockaddr_in*>(it->ifa_addr);
        if (inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf)) != nullptr) {
            result = buf;
            break;
        }
    }
    freeifaddrs(addrs);
    return result;
}

bool NICModule::interfaceIsUp(const std::string& iface)
{
    std::ifstream f("/sys/class/net/" + iface + "/operstate");
    if (!f.is_open()) return false;
    std::string state;
    std::getline(f, state);
    return state == "up";
}

NICInfo NICModule::readStats(const std::string& iface)
{
    NICInfo info;
    info.name        = iface;
    info.mac_address = readMac(iface);
    info.ipv4_address= readIPv4(iface);
    info.is_up       = interfaceIsUp(iface);

    std::ifstream f("/proc/net/dev");
    if (f.is_open()) {
        std::string line;
        while (std::getline(f, line)) {
            if (line.find(iface + ":") == std::string::npos) continue;
            std::istringstream ss(line);
            std::string name;
            ss >> name; // "eth0:"
            uint64_t dummy;
            ss >> info.stats.rx_bytes >> info.stats.rx_packets
               >> info.stats.rx_errors >> info.stats.rx_dropped
               >> dummy >> dummy >> dummy >> dummy
               >> info.stats.tx_bytes >> info.stats.tx_packets
               >> info.stats.tx_errors >> info.stats.tx_dropped;
            break;
        }
    }
    return info;
}
