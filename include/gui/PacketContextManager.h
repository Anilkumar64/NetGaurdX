#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  PacketContextManager
//
//  THE single source of truth for which packet is currently active.
//
//  Any widget that wants to act on a packet selection connects to:
//      contextChanged(PacketContext)
//
//  Any widget that wants to SET the selection calls:
//      setActivePacket(UnifiedPacket)
//
//  PacketContextManager also holds the matching Flow (if known) so views
//  don't have to look it up independently.
// ─────────────────────────────────────────────────────────────────────────────

#include <QObject>
#include <optional>
#include "core/AppController.h"  // UnifiedPacket, Flow, AppController

struct PacketContext
{
    // BUG1-FIX: shared_ptr — copying a PacketContext copies a pointer, not the packet bytes
    std::shared_ptr<const UnifiedPacket> packet;
    std::optional<Flow> flow;   // populated when a matching flow is known
    bool valid{false};
};

class PacketContextManager : public QObject
{
    Q_OBJECT

public:
    explicit PacketContextManager(AppController *app_ctrl, QObject *parent = nullptr);
    ~PacketContextManager() override;

    // BUG1-FIX: accept shared_ptr to avoid copying on the way in
    void setActivePacket(std::shared_ptr<const UnifiedPacket> pkt);
    void clearActivePacket();

    // Called by the flow view when a flow is selected
    void setActiveFlow(const Flow &flow);

    const PacketContext &current() const { return ctx_; }
    bool hasContext() const { return ctx_.valid; }

signals:
    // Emitted whenever the active packet changes — ALL views must subscribe to this
    void contextChanged(PacketContext ctx);

private slots:
    void onFlowCreated(Flow flow);
    void onFlowUpdated(Flow flow);
    void onFlowClosed(uint32_t flow_id);

private:
    std::optional<Flow> findFlow(uint32_t flow_id) const;

    AppController   *app_ctrl_{nullptr};
    PacketContext    ctx_;

    // Local flow cache so we can populate ctx_.flow without querying MonitoringEngine
    // every time (flows are updated frequently on the engine thread)
    std::unordered_map<uint32_t, Flow> flow_cache_;
};
