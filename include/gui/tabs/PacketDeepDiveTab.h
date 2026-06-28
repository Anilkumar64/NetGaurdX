#pragma once
// PacketDeepDiveTab — pure decode view, no stream table.
// The stream table is now PacketStreamPanel (left panel).
// This tab subscribes to PacketContextManager and renders
// layer-by-layer decode of whatever packet is active.
#include <QWidget>
#include <QTabWidget>
#include <QTextEdit>
#include <QLabel>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

class PacketDeepDiveTab : public QWidget {
    Q_OBJECT
public:
    explicit PacketDeepDiveTab(AppController        *app_ctrl,
                               PacketContextManager *ctx_mgr,
                               QWidget              *parent = nullptr);
public slots:
    void onContextChanged(PacketContext ctx);
private:
    void renderPacket(const UnifiedPacket &pkt, const std::optional<Flow> &flow);
    QString formatHex(const UnifiedPacket &pkt) const;

    QLabel      *summary_label_{nullptr};
    QLabel      *flow_label_{nullptr};
    QTabWidget  *detail_tabs_{nullptr};
    QTextEdit   *l2_view_{nullptr};
    QTextEdit   *l3_view_{nullptr};
    QTextEdit   *l4_view_{nullptr};
    QTextEdit   *hex_view_{nullptr};
};
