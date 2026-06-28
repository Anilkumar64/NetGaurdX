#include "core/troubleshooting/TroubleshootingEngine.h"
#include <sstream>

DiagnosticReport TroubleshootingEngine::diagnose(const NetworkMetrics& metrics, const std::vector<Flow>& flows, const std::vector<Event>& recent_events) {
    DiagnosticReport report;
    report.is_healthy = true;
    if (metrics.retransmission_rate.load() > 0.1) {
        report.l4_issues.push_back("High TCP retransmission rate: acknowledgements are missing or delayed, so TCP is resending data.");
        report.is_healthy = false;
    }
    if (metrics.dropped_packets.load() > 0) {
        report.l2_issues.push_back("Packet drops detected on capture or NIC path: inspect RX/TX rings, socket buffers, and interface pressure.");
        report.is_healthy = false;
    }
    if (flows.empty()) {
        report.l4_issues.push_back("No active flows observed: capture may be idle, filtered too tightly, or attached to the wrong interface.");
    }
    for (const auto& evt : recent_events) {
        if (evt.type == EventType::ALERT_DNS_FAILURE) {
            report.l7_issues.push_back(evt.description + ": DNS failed at the application layer; verify resolver reachability and response timing.");
            report.is_healthy = false;
        }
    }

    std::ostringstream summary;
    if (report.is_healthy) {
        summary << "System is healthy. Root cause reasoning: packet rates, drops, retransmissions, and decoded flows are within expected bounds.";
    } else {
        summary << "Issues detected. Root cause reasoning by layer:\n";
        auto appendIssues = [&summary](const char* layer, const std::vector<std::string>& issues) {
            for (const auto& issue : issues) {
                summary << "- " << layer << ": " << issue << "\n";
            }
        };
        appendIssues("L2", report.l2_issues);
        appendIssues("L3", report.l3_issues);
        appendIssues("L4", report.l4_issues);
        appendIssues("L7", report.l7_issues);
    }
    report.summary = summary.str();
    return report;
}
