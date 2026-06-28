#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QLabel>
#include <unordered_map>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

class TcpStateDiagramWidget;

class EndToEndFlowTab : public QWidget {
    Q_OBJECT
public:
    explicit EndToEndFlowTab(AppController *app_ctrl,
                             PacketContextManager *ctx_mgr,
                             QWidget *parent = nullptr);
public slots:
    void onFlowCreated(Flow flow);
    void onFlowUpdated(Flow flow);
    void onFlowClosed(uint32_t flow_id);
    void onAlert(Event evt);
    void onRetransmissionDetected(Event evt);
    void onTCPReset(Event evt);
    void onContextChanged(PacketContext ctx);
private:
    int  rowForFlow(uint32_t flow_id) const;
    void upsertFlow(const Flow &flow);
    void selectFlow(uint32_t flow_id);

    QTableWidget          *flow_table_{nullptr};
    QLabel                *context_label_{nullptr};
    TcpStateDiagramWidget *state_diagram_{nullptr};
    std::unordered_map<uint32_t, Flow> flows_;
    uint32_t selected_flow_id_{0};
    PacketContextManager *ctx_mgr_{nullptr};
};
