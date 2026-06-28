#include <memory>
#pragma once
#include <QWidget>
#include <QLabel>
#include <QTextEdit>
#include <vector>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

class ActionCard;

class AutoHealingTab : public QWidget {
    Q_OBJECT
public:
    explicit AutoHealingTab(AppController *app_ctrl, PacketContextManager *ctx_mgr, QWidget *parent = nullptr);
public slots:
    void onHealingActionsSuggested(std::vector<HealingAction> actions);
    void onDiagnosticsComplete(DiagnosticReport report);
    void onHealingAction(Event evt);
    void onSelectedPacket(std::shared_ptr<const UnifiedPacket> pkt);
    void onContextChanged(PacketContext ctx);
private:
    QLabel     *selected_packet_label_{nullptr};
    ActionCard *action_card_{nullptr};
    QTextEdit  *history_log_{nullptr};
    AppController *app_ctrl_{nullptr};
    std::vector<HealingAction> pending_actions_;
    Protocol  last_proto_{Protocol::UNKNOWN};
    uint8_t   last_flags_{0xFF};
};
