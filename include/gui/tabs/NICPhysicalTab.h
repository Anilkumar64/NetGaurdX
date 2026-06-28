#include <memory>
#pragma once
#include <QWidget>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

class NicStatsCard;
class FrameDecodeCard;
class QTimer;

class NICPhysicalTab : public QWidget {
    Q_OBJECT
public:
    explicit NICPhysicalTab(AppController *app_ctrl, PacketContextManager *ctx_mgr, QWidget *parent = nullptr);
public slots:
    void onSelectedPacket(std::shared_ptr<const UnifiedPacket> pkt);
    void refreshNICCounters();
    void onContextChanged(PacketContext ctx);
private:
    void updateNICCounters(const NetworkMetrics &metrics);

    AppController  *app_ctrl_{nullptr};
    QTimer         *counter_refresh_timer_{nullptr};
    NicStatsCard   *nic_card_{nullptr};
    FrameDecodeCard *frame_card_{nullptr};
};
