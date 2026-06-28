#pragma once
#include "core/models/MetricsModel.h"
#include "core/models/FlowModel.h"
#include "core/eventbus/EventBus.h"
#include <vector>
#include <string>

struct DiagnosticReport
{
    bool is_healthy{true};
    std::string summary;
    std::vector<std::string> l2_issues;
    std::vector<std::string> l3_issues;
    std::vector<std::string> l4_issues;
    std::vector<std::string> l7_issues;
};

class TroubleshootingEngine
{
public:
    DiagnosticReport diagnose(const NetworkMetrics &metrics,
                              const std::vector<Flow> &flows,
                              const std::vector<Event> &recent_events);
};