#pragma once
// Register all custom types used in Qt signals for cross-thread delivery
#include <QMetaType>
#include <memory>
#include "core/models/PacketModel.h"
#include "core/models/FlowModel.h"
#include "core/models/MetricsModel.h"
#include "core/eventbus/EventBus.h"
#include "core/healing/AutoHealingEngine.h"
#include "core/troubleshooting/TroubleshootingEngine.h"

// BUG1-FIX: Register the shared_ptr type used in all packet-carrying signals.
// UnifiedPacket value type kept for any remaining internal uses (e.g. testing).
Q_DECLARE_METATYPE(std::shared_ptr<const UnifiedPacket>)
Q_DECLARE_METATYPE(UnifiedPacket)
Q_DECLARE_METATYPE(Flow)
Q_DECLARE_METATYPE(NetworkMetrics)
Q_DECLARE_METATYPE(SystemHealth)
Q_DECLARE_METATYPE(Event)
Q_DECLARE_METATYPE(std::vector<HealingAction>)
Q_DECLARE_METATYPE(HealingResult)
Q_DECLARE_METATYPE(DiagnosticReport)

inline void registerMetaTypes()
{
    // BUG1-FIX: shared_ptr type registration for queued cross-thread connections
    qRegisterMetaType<std::shared_ptr<const UnifiedPacket>>("std::shared_ptr<const UnifiedPacket>");
    qRegisterMetaType<UnifiedPacket>("UnifiedPacket");
    qRegisterMetaType<Flow>("Flow");
    qRegisterMetaType<NetworkMetrics>("NetworkMetrics");
    qRegisterMetaType<SystemHealth>("SystemHealth");
    qRegisterMetaType<Event>("Event");
    qRegisterMetaType<std::vector<HealingAction>>("std::vector<HealingAction>");
    qRegisterMetaType<HealingResult>("HealingResult");
    qRegisterMetaType<DiagnosticReport>("DiagnosticReport");
    qRegisterMetaType<uint32_t>("uint32_t");
}
 
