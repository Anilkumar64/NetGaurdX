#include <memory>
#pragma once
#include <QWidget>
#include <QLabel>
#include <map>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

class SparklineWidget;
class ProtocolBar;
class AlertTicker;
class PacketContextCard;

class NetworkOverviewTab : public QWidget {
    Q_OBJECT
public:
    explicit NetworkOverviewTab(AppController* app_ctrl, PacketContextManager *ctx_mgr, QWidget* parent = nullptr);
public slots:
    void onMetricsUpdated(NetworkMetrics metrics);
    void onHealthChanged(SystemHealth health);
    void onAlert(Event evt);
    void onSelectedPacket(std::shared_ptr<const UnifiedPacket> pkt);
    void onContextChanged(PacketContext ctx);
    void onPacketReceived(std::shared_ptr<const UnifiedPacket> pkt);
private:
    QLabel* pps_label_{nullptr};
    QLabel* bps_label_{nullptr};
    QLabel* flows_label_{nullptr};
    QLabel* packets_label_{nullptr};
    QLabel* health_label_{nullptr};
    SparklineWidget* pps_spark_{nullptr};
    SparklineWidget* bps_spark_{nullptr};
    ProtocolBar* proto_bar_{nullptr};
    AlertTicker* alert_ticker_{nullptr};
    PacketContextCard* packet_card_{nullptr};
    AppController* app_ctrl_{nullptr};
    std::map<Protocol, int> proto_counts_;
    int total_proto_count_{0};
};
