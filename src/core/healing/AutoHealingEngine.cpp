#include "core/healing/AutoHealingEngine.h"
#include "core/Logger.h"

#include <cstdlib>
#include <string>
#include <unordered_set>
#include <sys/wait.h>

namespace {
const std::unordered_set<std::string>& permittedCommands()
{
    static const std::unordered_set<std::string> commands{
        "tcpkill",
        "resolvectl flush-caches",
        "ip -s link",
    };
    return commands;
}

int runCommand(const std::string& command)
{
    const int status = std::system(command.c_str());
    if (status == -1) {
        return -1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return status;
}
}

std::vector<HealingAction> AutoHealingEngine::suggestActions(const DiagnosticReport& report) {
    std::vector<HealingAction> actions;
    if (!report.is_healthy) {
        actions.push_back({"RESET_CONN", "Reset stuck connections", "tcpkill", true});
        actions.push_back({"FLUSH_DNS", "Flush local DNS resolver cache", "resolvectl flush-caches", false});
    } else {
        actions.push_back({"VERIFY_STACK", "Verify TCP/IP stack health", "ip -s link", false});
    }
    return actions;
}

HealingResult AutoHealingEngine::executeAction(const HealingAction& action) {
    HealingResult result;
    result.action = action;

    if (permittedCommands().find(action.command) == permittedCommands().end()) {
        result.message = "Blocked non-whitelisted healing command";
        Logger::instance().log(LogLevel::WARN, "HEALING",
            "blocked non-whitelisted healing command: " + action.command);
        return result;
    }

    Logger::instance().log(LogLevel::INFO, "HEALING",
        "executing healing command: " + action.command);
    result.executed = true;
    result.exit_code = runCommand(action.command);
    result.success = result.exit_code == 0;
    if (!result.success) {
        result.message = "Healing command failed";
        Logger::instance().log(LogLevel::WARN, "HEALING",
            "healing command failed with exit code " + std::to_string(result.exit_code) +
            ": " + action.command);
        return result;
    }

    result.message = "Healing command succeeded";
    Logger::instance().log(LogLevel::INFO, "HEALING",
        "healing command succeeded with exit code 0: " + action.command);
    return result;
}
