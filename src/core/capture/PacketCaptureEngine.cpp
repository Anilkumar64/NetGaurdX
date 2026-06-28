#include "core/capture/PacketCaptureEngine.h"
#include "core/Logger.h"
#include "core/eventbus/EventBus.h"
#include "core/parser/PacketParserPipeline.h"
#include <chrono>

std::vector<std::string> PacketCaptureEngine::listInterfaces() {
  std::vector<std::string> ifaces;
  pcap_if_t *alldevs = nullptr;
  char errbuf[PCAP_ERRBUF_SIZE] = {};
  if (pcap_findalldevs(&alldevs, errbuf) == 0) {
    for (pcap_if_t *d = alldevs; d; d = d->next)
      ifaces.push_back(d->name);
    pcap_freealldevs(alldevs);
  }
  return ifaces;
}

bool PacketCaptureEngine::start(const std::string &interface_name,
                                const std::string &bpf_filter) {
  last_error_.clear();
  char errbuf[PCAP_ERRBUF_SIZE] = {};
  pcap_handle_ = pcap_open_live(interface_name.c_str(), 65535, 1, 100, errbuf);
  if (!pcap_handle_) {
    last_error_ = errbuf;
    Logger::instance().log(LogLevel::ERROR, "CAPTURE",
                           "pcap_open_live failed: " + last_error_);
    return false;
  }

  if (!bpf_filter.empty()) {
    struct bpf_program fp;
    if (pcap_compile(pcap_handle_, &fp, bpf_filter.c_str(), 0,
                     PCAP_NETMASK_UNKNOWN) != -1) {
      pcap_setfilter(pcap_handle_, &fp);
      pcap_freecode(&fp);
    } else {
      last_error_ = pcap_geterr(pcap_handle_);
      Logger::instance().log(LogLevel::ERROR, "CAPTURE",
                             "pcap_compile failed: " + last_error_);
      pcap_close(pcap_handle_);
      pcap_handle_ = nullptr;
      return false;
    }
  }

  interface_ = interface_name;
  running_ = true;
  capture_thread_ = std::thread(&PacketCaptureEngine::captureLoop, this);
  EventBus::instance().publish({EventType::CAPTURE_STARTED, 0.0,
                                "Started capture", "APP", "INFO",
                                std::string()});
  return true;
}

void PacketCaptureEngine::stop() {
  if (running_) {
    running_ = false;
    if (pcap_handle_)
      pcap_breakloop(pcap_handle_);
    if (capture_thread_.joinable())
      capture_thread_.join();
    if (pcap_handle_) {
      pcap_close(pcap_handle_);
      pcap_handle_ = nullptr;
    }
    EventBus::instance().publish({EventType::CAPTURE_STOPPED, 0.0,
                                  "Stopped capture", "APP", "INFO",
                                  std::string()});
  }
}

void PacketCaptureEngine::captureLoop() {
  Logger::instance().log(LogLevel::INFO, "CAPTURE",
                         "pcap loop started on " + interface_);
  while (running_) {

    int dispatched = pcap_dispatch(pcap_handle_, 100, pcapCallback,
                                   reinterpret_cast<u_char *>(this));

    if (dispatched == PCAP_ERROR_BREAK) {
      break;
    }
    if (dispatched == PCAP_ERROR) {
      Logger::instance().log(LogLevel::ERROR, "CAPTURE",
                             "pcap_dispatch failed: " +
                                 std::string(pcap_geterr(pcap_handle_)));
      break;
    }
  }
}

void PacketCaptureEngine::pcapCallback(u_char *user,
                                       const struct pcap_pkthdr *pkthdr,
                                       const u_char *packet) {
  auto *engine = reinterpret_cast<PacketCaptureEngine *>(user);
  if (!engine->running_)
    return;

  double ts = pkthdr->ts.tv_sec + pkthdr->ts.tv_usec / 1000000.0;
  Logger::instance().log(LogLevel::DEBUG, "CAPTURE",
                         "packet received len=" + std::to_string(pkthdr->len) +
                             " ts=" + std::to_string(ts));

  // BUG1-FIX: parse() now returns shared_ptr — zero copying from here on
  auto pkt =
      PacketParserPipeline::parse(engine->next_id_++, packet, pkthdr->len, ts);
  if (engine->callback_)
    engine->callback_(pkt);
  EventBus::instance().publish(
      {EventType::PACKET_CAPTURED, ts, "Captured packet", "L2", "INFO", pkt});
}
