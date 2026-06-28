#include "gui/PacketContextManager.h"
#include "core/Logger.h"

PacketContextManager::PacketContextManager(AppController *app_ctrl, QObject *parent)
    : QObject(parent), app_ctrl_(app_ctrl)
{
    app_ctrl_->setPacketContextManager(this);

    // Keep a local flow cache so we can attach a flow to any selected packet instantly
    connect(app_ctrl_, &AppController::flowCreated,  this, &PacketContextManager::onFlowCreated);
    connect(app_ctrl_, &AppController::flowUpdated,  this, &PacketContextManager::onFlowUpdated);
    connect(app_ctrl_, &AppController::flowClosed,   this, &PacketContextManager::onFlowClosed);
}

PacketContextManager::~PacketContextManager()
{
    if (app_ctrl_) {
        app_ctrl_->setPacketContextManager(nullptr);
    }
}

void PacketContextManager::setActivePacket(std::shared_ptr<const UnifiedPacket> pkt)
{
    if (!pkt) return;
    Logger::instance().log(LogLevel::DEBUG, "CTX", "setActivePacket #" + std::to_string(pkt->id));

    ctx_.packet = pkt;
    ctx_.flow   = findFlow(pkt->flow_id);
    ctx_.valid  = true;

    app_ctrl_->selectPacket(pkt);

    emit contextChanged(ctx_);
}

void PacketContextManager::clearActivePacket()
{
    Logger::instance().log(LogLevel::DEBUG, "CTX", "clearActivePacket");
    ctx_ = PacketContext{};
    emit contextChanged(ctx_);
}

void PacketContextManager::setActiveFlow(const Flow &flow)
{
    // Update the flow on the current context without changing the packet
    ctx_.flow = flow;
    if (ctx_.valid)
        emit contextChanged(ctx_);
}

void PacketContextManager::onFlowCreated(Flow flow)
{
    flow_cache_[flow.flow_id] = std::move(flow);
}

void PacketContextManager::onFlowUpdated(Flow flow)
{
    flow_cache_[flow.flow_id] = flow;

    // If the currently-active packet belongs to this flow, refresh the context
    if (ctx_.valid && ctx_.packet && ctx_.packet->flow_id == flow.flow_id) {
        ctx_.flow = flow;
        emit contextChanged(ctx_);
    }
}

void PacketContextManager::onFlowClosed(uint32_t flow_id)
{
    flow_cache_.erase(flow_id);
}

std::optional<Flow> PacketContextManager::findFlow(uint32_t flow_id) const
{
    auto it = flow_cache_.find(flow_id);
    if (it != flow_cache_.end())
        return it->second;
    return std::nullopt;
}
