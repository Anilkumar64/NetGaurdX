#include "core/AppController.h"
#include "core/Logger.h"
#include "gui/PacketContextManager.h"
#include <algorithm>
#include <unistd.h>

namespace {

bool containsInterface(const std::vector<std::string> &interfaces,
                       const std::string &name) {
  return std::find(interfaces.begin(), interfaces.end(), name) !=
         interfaces.end();
}

std::string firstUsableInterface(const std::vector<std::string> &interfaces) {
  auto non_loopback = std::find_if(
      interfaces.begin(), interfaces.end(),
      [](const std::string &name) { return !name.empty() && name != "lo"; });
  if (non_loopback != interfaces.end()) {
    return *non_loopback;
  }
  return interfaces.empty() ? std::string{} : interfaces.front();
}

} // namespace

AppController::AppController(QObject *parent) : QObject(parent) {
  real_capture_ = std::make_unique<PacketCaptureEngine>();
  simulated_source_ = std::make_unique<SimulatedPacketSource>(40);

  monitoring_engine_.start();

  auto isAlertEvent = [](EventType type) {
    return type == EventType::ALERT_DNS_FAILURE ||
           type == EventType::ALERT_PACKET_LOSS ||
           type == EventType::ALERT_HIGH_RETRANSMISSION ||
           type == EventType::ALERT_TCP_RESET;
  };

  auto routeEvent = [this, isAlertEvent](const Event &evt) {
    if (isAlertEvent(evt.type)) {
      std::lock_guard<std::mutex> lock(recent_events_mutex_);
      recent_events_.push_back(evt);
      // BUG6-FIX: deque::pop_front is O(1); was vector::erase from front = O(N)
      while (recent_events_.size() > 100)
        recent_events_.pop_front();
    }

    QMetaObject::invokeMethod(
        this,
        [this, evt]() {
          switch (evt.type) {
          case EventType::PACKET_CAPTURED:
            try {
              // BUG1-FIX: payload now holds shared_ptr — no copy of raw_data
              const auto pkt =
                  std::any_cast<std::shared_ptr<const UnifiedPacket>>(
                      evt.payload);
              if (!pkt || !acceptsPacket(*pkt)) {
                return;
              }
              emit newEvent(evt);
              emit packetReceived(pkt);
              if (!hasSelectedPacket()) {
                selectPacket(pkt);
              }
            } catch (const std::bad_any_cast &) {
              Logger::instance().log(LogLevel::WARN, "APPCTRL",
                                     "PACKET_CAPTURED payload type mismatch");
            }
            break;
          case EventType::FLOW_CREATED:
            emit newEvent(evt);
            try {
              emit flowCreated(std::any_cast<Flow>(evt.payload));
            } catch (const std::bad_any_cast &) {
              Logger::instance().log(LogLevel::WARN, "APPCTRL",
                                     "FLOW_CREATED payload type mismatch");
            }
            break;
          case EventType::FLOW_UPDATED:
            emit newEvent(evt);
            try {
              emit flowUpdated(std::any_cast<Flow>(evt.payload));
            } catch (const std::bad_any_cast &) {
              Logger::instance().log(LogLevel::WARN, "APPCTRL",
                                     "FLOW_UPDATED payload type mismatch");
            }
            break;
          case EventType::FLOW_CLOSED:
            emit newEvent(evt);
            try {
              emit flowClosed(std::any_cast<uint32_t>(evt.payload));
            } catch (const std::bad_any_cast &) {
              Logger::instance().log(LogLevel::WARN, "APPCTRL",
                                     "FLOW_CLOSED payload type mismatch");
            }
            break;
          case EventType::ALERT_DNS_FAILURE:
          case EventType::ALERT_PACKET_LOSS:
          case EventType::ALERT_HIGH_RETRANSMISSION:
          case EventType::ALERT_TCP_RESET:
          case EventType::HEALING_ACTION:
            emit newEvent(evt);
            emit alertTriggered(evt);
            break;
          case EventType::METRICS_UPDATED:
            emit newEvent(evt);
            emit metricsUpdated(monitoring_engine_.getMetricsCopy());
            emit healthChanged(getCurrentHealth());
            break;
          case EventType::CAPTURE_STARTED:
            emit newEvent(evt);
            emit captureStateChanged(use_simulation_.load() ? "SIMULATED"
                                                            : "LIVE");
            break;
          case EventType::CAPTURE_STOPPED:
            emit newEvent(evt);
            emit captureStateChanged("STOPPED");
            break;
          case EventType::INTERFACE_CHANGED:
            emit newEvent(evt);
            emit captureStateChanged(use_simulation_.load() ? "SIMULATED"
                                                            : "LIVE");
            break;
          }
        },
        Qt::QueuedConnection);
  };

  // PACKET_CAPTURED is invoked on the capture/simulation publisher thread;
  // token is stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::PACKET_CAPTURED, routeEvent));
  // FLOW_CREATED is invoked on the monitoring publisher thread; token is stored
  // for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::FLOW_CREATED, routeEvent));
  // FLOW_UPDATED is invoked on the monitoring publisher thread; token is stored
  // for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::FLOW_UPDATED, routeEvent));
  // FLOW_CLOSED is invoked on the monitoring publisher thread; token is stored
  // for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::FLOW_CLOSED, routeEvent));
  // ALERT_DNS_FAILURE is invoked on its EventBus publisher thread; token is
  // stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::ALERT_DNS_FAILURE, routeEvent));
  // ALERT_PACKET_LOSS is invoked on its EventBus publisher thread; token is
  // stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::ALERT_PACKET_LOSS, routeEvent));
  // ALERT_HIGH_RETRANSMISSION is invoked on the monitoring publisher thread;
  // token is stored for destructor unsubscribe.
  eventbus_tokens_.push_back(EventBus::instance().subscribe(
      EventType::ALERT_HIGH_RETRANSMISSION, routeEvent));
  // ALERT_TCP_RESET is invoked on the monitoring publisher thread; token is
  // stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::ALERT_TCP_RESET, routeEvent));
  // METRICS_UPDATED is invoked on the monitoring timer thread; token is stored
  // for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::METRICS_UPDATED, routeEvent));
  // HEALING_ACTION is invoked on the healing action publisher thread; token is
  // stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::HEALING_ACTION, routeEvent));
  // CAPTURE_STARTED is invoked on the capture control caller thread; token is
  // stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::CAPTURE_STARTED, routeEvent));
  // CAPTURE_STOPPED is invoked on the capture control caller thread; token is
  // stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::CAPTURE_STOPPED, routeEvent));
  // INTERFACE_CHANGED is invoked on the capture control caller thread; token is
  // stored for destructor unsubscribe.
  eventbus_tokens_.push_back(
      EventBus::instance().subscribe(EventType::INTERFACE_CHANGED, routeEvent));

  metrics_timer_ = new QTimer(this);
  connect(metrics_timer_, &QTimer::timeout, this, [this]() {
    emit metricsUpdated(monitoring_engine_.getMetricsCopy());
    emit healthChanged(getCurrentHealth());
  });
  metrics_timer_->start(1000);
}

AppController::~AppController() {
  for (auto token : eventbus_tokens_) {
    EventBus::instance().unsubscribe(token);
  }
  stopCapture();
  monitoring_engine_.stop();
}

bool AppController::startCapture(const QString &interface_name,
                                 const QString &bpf_filter) {
  std::string iface = interface_name.trimmed().toStdString();
  stopCapture();

  const auto pcap_interfaces = PacketCaptureEngine::listInterfaces();
  if (!iface.empty() && !pcap_interfaces.empty() &&
      !containsInterface(pcap_interfaces, iface)) {
    const std::string fallback = firstUsableInterface(pcap_interfaces);
    if (!fallback.empty()) {
      Logger::instance().log(LogLevel::WARN, "CAPTURE",
                             "requested interface '" + iface +
                                 "' is unavailable; using '" + fallback + "'");
      iface = fallback;
    }
  }

  if (iface.empty()) {
    iface = firstUsableInterface(pcap_interfaces);
  }
  if (iface.empty()) {
    iface = firstUsableInterface(nic_module_.listInterfaces());
  }
  if (iface.empty()) {
    const QString message =
        "Live capture failed: no network interfaces are available";
    Logger::instance().log(LogLevel::WARN, "CAPTURE", message.toStdString());
    emit captureStateChanged("STOPPED");
    emit captureError(message);
    return false;
  }

  EventBus::instance().publish({EventType::INTERFACE_CHANGED, 0.0,
                                "Interface changed to " + iface, "APP", "INFO",
                                iface});

  if (getuid() != 0) {
    Logger::instance().log(LogLevel::WARN, "CAPTURE",
                           "not root - switching to simulation mode");
    use_simulation_ = true;
  } else {
    use_simulation_ = false;
  }

  if (use_simulation_) {
    simulated_source_->setPacketCallback(
        [this](std::shared_ptr<const UnifiedPacket> pkt) {
          if (pkt && acceptsPacket(*pkt)) {
            monitoring_engine_.ingestPacket(*pkt);
          }
        });
    simulated_source_->start();
    emit captureStateChanged("SIMULATED");
  } else {
    real_capture_->setPacketCallback(
        [this](std::shared_ptr<const UnifiedPacket> pkt) {
          if (pkt && acceptsPacket(*pkt)) {
            monitoring_engine_.ingestPacket(*pkt);
          }
        });
    if (real_capture_->start(iface, bpf_filter.trimmed().toStdString())) {
      emit captureStateChanged("LIVE");
    } else {
      const QString error = QString::fromStdString(real_capture_->lastError());
      const QString message = error.isEmpty() ? "Live capture failed"
                                              : "Live capture failed: " + error;
      Logger::instance().log(LogLevel::WARN, "CAPTURE", message.toStdString());
      emit captureStateChanged("STOPPED");
      emit captureError(message);
      return false;
    }
  }

  Logger::instance().log(LogLevel::INFO, "APPCTRL",
                         "capture started, simulated=" +
                             std::to_string(use_simulation_.load()));

  EventBus::instance().publish({EventType::CAPTURE_STARTED, 0.0,
                                "Capture started", "APP", "INFO",
                                std::string{}});
  return true;
}

void AppController::stopCapture() {
  simulated_source_->stop();
  real_capture_->stop();
  // Reset selected packet so the next capture auto-selects the first packet
  {
    std::lock_guard<std::mutex> lock(selected_packet_mutex_);
    selected_packet_ =
        nullptr; // BUG1-FIX: was has_selected_packet_ = false (removed field)
  }
  if (ctx_mgr_) {
    ctx_mgr_->clearActivePacket();
  }
  EventBus::instance().publish({EventType::CAPTURE_STOPPED, 0.0,
                                "Capture stopped", "APP", "INFO",
                                std::string{}});
}

SystemHealth AppController::getCurrentHealth() {
  SystemHealth h;
  auto metrics = monitoring_engine_.getMetricsCopy();
  if (metrics.dropped_packets.load() > 0 ||
      metrics.retransmission_rate.load() > 0.05) {
    h.overall = HealthStatus::DEGRADED;
    h.network_health = HealthStatus::DEGRADED;
    h.status_message = "DEGRADED";
  } else {
    h.status_message = "OK";
  }
  return h;
}

void AppController::applyFilter(const QString &filter) {
  PacketFilter candidate;
  if (!candidate.parse(filter.toStdString())) {
    Logger::instance().log(LogLevel::WARN, "APPCTRL",
                           "filter rejected: " + candidate.getError());
    return;
  }

  std::lock_guard<std::mutex> lock(packet_filter_mutex_);
  packet_filter_ = candidate;
  Logger::instance().log(LogLevel::INFO, "APPCTRL",
                         filter.isEmpty() ? "packet filter cleared"
                                          : "packet filter applied: " +
                                                filter.toStdString());
}

void AppController::runDiagnostics() {
  // BUG6-FIX: recent_events_ is now deque; copy into a vector for the engine
  // API
  std::vector<Event> recent_events;
  {
    std::lock_guard<std::mutex> lock(recent_events_mutex_);
    recent_events.assign(recent_events_.begin(), recent_events_.end());
  }

  DiagnosticReport report = troubleshooting_engine_.diagnose(
      monitoring_engine_.getMetricsCopy(), monitoring_engine_.getActiveFlows(),
      recent_events);
  std::vector<HealingAction> actions = healing_engine_.suggestActions(report);
  emit diagnosticsComplete(report);
  emit healingActionsSuggested(actions);
}

void AppController::executeHealing(const HealingAction &action) {
  const HealingResult result = healing_engine_.executeAction(action);
  EventBus::instance().publish(
      {EventType::HEALING_ACTION, 0.0,
       (result.success ? "Healing succeeded: " : "Healing failed: ") +
           action.description + " (exit code " +
           std::to_string(result.exit_code) + ")",
       "APP", result.success ? "INFO" : "WARN", result});
  Logger::instance().log(LogLevel::INFO, "APPCTRL",
                         "healing action result: " + action.description +
                             ", executed=" + std::to_string(result.executed) +
                             ", exit_code=" + std::to_string(result.exit_code));
}

bool AppController::hasSelectedPacket() const {
  std::lock_guard<std::mutex> lock(selected_packet_mutex_);
  return selected_packet_ != nullptr;
}

// BUG1-FIX: returns shared_ptr — caller gets pointer copy, not a 350KB deep
// copy
std::shared_ptr<const UnifiedPacket> AppController::selectedPacket() const {
  std::lock_guard<std::mutex> lock(selected_packet_mutex_);
  return selected_packet_;
}

// BUG1-FIX: accepts shared_ptr to avoid copying on the way in
// BUG7-FIX: copy the shared_ptr, release the mutex, THEN emit — prevents
// deadlock
//   if any connected slot calls selectedPacket() (which also acquires the
//   mutex).
void AppController::selectPacket(std::shared_ptr<const UnifiedPacket> pkt) {
  std::shared_ptr<const UnifiedPacket> to_emit;
  {
    std::lock_guard<std::mutex> lock(selected_packet_mutex_);
    selected_packet_ = pkt;
    to_emit = pkt;
  } // lock released here — safe to emit now
  emit selectedPacketChanged(to_emit);
}

bool AppController::acceptsPacket(const UnifiedPacket &pkt) const {
  std::lock_guard<std::mutex> lock(packet_filter_mutex_);
  return packet_filter_.matches(pkt);
}
