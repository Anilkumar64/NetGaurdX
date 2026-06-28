#pragma once
#include "core/models/PacketModel.h"
#include <pcap.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <memory>

class PacketCaptureEngine
{
public:
    PacketCaptureEngine() = default;
    ~PacketCaptureEngine() { stop(); }

    /// Returns names of all network interfaces visible to libpcap.
    static std::vector<std::string> listInterfaces();

    /// Open the interface and start the capture thread.
    /// Returns false if pcap_open_live fails (e.g., no permission or bad iface).
    bool start(const std::string &interface_name,
               const std::string &bpf_filter = "");

    /// Signal the capture thread to stop and wait for it to exit.
    void stop();

    bool isRunning() const { return running_.load(); }
    std::string lastError() const { return last_error_; }

    void setPacketCallback(std::function<void(std::shared_ptr<const UnifiedPacket>)> cb)
    {
        callback_ = std::move(cb);
    }

private:
    void captureLoop();

    /// libpcap raw callback (static forwarder).
    static void pcapCallback(u_char *user,
                             const struct pcap_pkthdr *pkthdr,
                             const u_char *packet);

    pcap_t *pcap_handle_{nullptr};
    std::string interface_;
    std::string last_error_;
    std::atomic<bool> running_{false};
    std::thread capture_thread_;
    std::function<void(std::shared_ptr<const UnifiedPacket>)> callback_;
    uint64_t next_id_{1};
};
