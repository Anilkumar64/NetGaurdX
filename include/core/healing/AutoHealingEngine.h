#pragma once
#include "core/troubleshooting/TroubleshootingEngine.h"
#include <vector>
#include <string>

struct HealingAction
{
    std::string id;
    std::string description;
    std::string command; // shell command, executed only if whitelisted
    bool requires_root{false};
};

struct HealingResult
{
    HealingAction action;
    bool executed{false};
    bool success{false};
    int exit_code{-1};
    std::string message;
};

class AutoHealingEngine
{
public:
    /// Inspect the diagnostic report and produce a list of suggested actions.
    std::vector<HealingAction> suggestActions(const DiagnosticReport &report);

    /// Execute the given whitelisted action and return the real process exit code.
    HealingResult executeAction(const HealingAction &action);
};
