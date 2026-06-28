#include <memory>
#pragma once
#include <QWidget>
#include <QLabel>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

class GaugeBar;
class FlowCanvas;
class HistoryChart;

class BuffersQueuesTab : public QWidget {
    Q_OBJECT
public:
    explicit BuffersQueuesTab(AppController *app_ctrl, PacketContextManager *ctx_mgr, QWidget *parent = nullptr);
public slots:
    void onDropDetected(Event evt);
    void onSelectedPacket(std::shared_ptr<const UnifiedPacket> pkt);
    void onContextChanged(PacketContext ctx);
private:
    QLabel       *selected_packet_label_{nullptr};
    GaugeBar     *rx_gauge_{nullptr};
    GaugeBar     *tx_gauge_{nullptr};
    GaugeBar     *sock_gauge_{nullptr};
    FlowCanvas   *flow_canvas_{nullptr};
    HistoryChart *history_chart_{nullptr};
};
