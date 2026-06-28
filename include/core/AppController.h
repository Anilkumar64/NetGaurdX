#pragma once
#include <QObject>
#include <QTimer>
#include <memory>
#include <atomic>
#include <vector>
#include <deque>
#include <mutex>
#include <optional>

#include "core/capture/PacketCaptureEngine.h"
#include "core/capture/SimulatedPacketSource.h"
#include "core/monitoring/MonitoringEngine.h"
#include "core/troubleshooting/TroubleshootingEngine.h"
#include "core/healing/AutoHealingEngine.h"
#include "core/nic/NICModule.h"
#include "core/buffers/BufferModel.h"
#include "core/PacketFilter.h"
#include "core/eventbus/EventBus.h"

class AppController : public QObject
{
    Q_OBJECT

public:
    explicit AppController(QObject *parent = nullptr);
    ~AppController() override;

    bool            isSimulated()        const { return use_simulation_.load(); }
    NetworkMetrics  getMetricsCopy()           { return monitoring_engine_.getMetricsCopy(); }
    SystemHealth    getCurrentHealth();
    std::vector<Flow> getActiveFlows()   const { return monitoring_engine_.getActiveFlows(); }
    BufferMonitor&  getBufferMonitor()         { return buffer_monitor_; }
    NICModule&      getNICModule()             { return nic_module_; }
    void            setPacketContextManager(class PacketContextManager *ctx_mgr) { ctx_mgr_ = ctx_mgr; }
    bool            hasSelectedPacket()  const;
    // BUG1-FIX: return shared_ptr instead of a full copy of the packet
    std::shared_ptr<const UnifiedPacket> selectedPacket() const;

public slots:
    bool startCapture(const QString &interface_name, const QString &bpf_filter = {});
    void stopCapture();
    void applyFilter(const QString &filter);
    void runDiagnostics();
    void executeHealing(const HealingAction &action);
    // BUG1-FIX: accept shared_ptr to avoid copying on the way in
    void selectPacket(std::shared_ptr<const UnifiedPacket> pkt);

signals:
    // BUG1-FIX: all packet-carrying signals use shared_ptr — pointer copy only
    void packetReceived(std::shared_ptr<const UnifiedPacket> pkt);
    void flowCreated(Flow flow);
    void flowUpdated(Flow flow);
    void flowClosed(uint32_t flow_id);
    void metricsUpdated(NetworkMetrics metrics);
    void healthChanged(SystemHealth health);
    void newEvent(Event evt);
    void alertTriggered(Event evt);
    void healingActionsSuggested(std::vector<HealingAction> actions);
    void diagnosticsComplete(DiagnosticReport report);
    void captureStateChanged(QString mode);
    void captureError(QString message);
    // BUG1-FIX: shared_ptr to avoid copying the selected packet to every subscriber
    void selectedPacketChanged(std::shared_ptr<const UnifiedPacket> pkt);

private:
    std::unique_ptr<PacketCaptureEngine>   real_capture_;
    std::unique_ptr<SimulatedPacketSource> simulated_source_;
    MonitoringEngine    monitoring_engine_;
    TroubleshootingEngine troubleshooting_engine_;
    AutoHealingEngine   healing_engine_;
    NICModule           nic_module_;
    BufferMonitor       buffer_monitor_;
    PacketFilter        packet_filter_;
    mutable std::mutex  packet_filter_mutex_;
    // BUG1-FIX: store as shared_ptr — single allocation shared everywhere
    std::shared_ptr<const UnifiedPacket> selected_packet_;
    mutable std::mutex  selected_packet_mutex_;
    // BUG6-FIX: use deque so pop_front is O(1) instead of O(N) vector erase
    std::deque<Event>   recent_events_;
    mutable std::mutex  recent_events_mutex_;

    std::atomic<bool> use_simulation_{false};
    QTimer*           metrics_timer_{nullptr};
    class PacketContextManager *ctx_mgr_{nullptr};

    bool acceptsPacket(const UnifiedPacket& pkt) const;

    std::vector<EventBus::SubToken> eventbus_tokens_;
};
