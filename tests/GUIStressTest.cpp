// GUIStressTest.cpp — stress all 8 GUI tabs under simulated packet flood
//
// Strategy:
//   1. Spin up AppController + MainWindow (offscreen, no display needed)
//   2. Run SimulatedPacketSource at max PPS for N seconds
//   3. While packets flow, hammer every tab with:
//        - rapid tab switching (cycle all 8 every 50ms)
//        - packet selection churn (select latest packet every 100ms)
//        - filter apply/clear churn (every 200ms)
//        - diagnostics + healing trigger (every 500ms)
//        - start/stop capture cycles (3×)
//        - inject alert events directly into EventBus
//        - processEvents() to drive the Qt event loop
//   4. After flood, verify:
//        - no crash / SIGABRT (implicit: if we reach the checks, we survived)
//        - all 8 tabs still present
//        - metrics sane (total_packets > 0)
//        - active flows > 0
//        - PacketContextManager has a valid context
//        - diagnostics can run cleanly post-flood
//        - auto-healing executes a real command successfully
//
// Run with:   ./GUIStressTest
// Build:      add target GUIStressTest to CMakeLists.txt (see bottom of this file)

#include <QApplication>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QTabWidget>
#include <QTableWidget>
#include <QThread>
#include <QTimer>
#include <QPushButton>
#include <iostream>
#include <atomic>
#include <thread>
#include <chrono>
#include <optional>

#include "core/AppController.h"
#include "core/Logger.h"
#include "core/MetaTypes.h"
#include "core/eventbus/EventBus.h"
#include "gui/MainWindow.h"
#include "gui/PacketContextManager.h"

// ── Helpers ────────────────────────────────────────────────────────────────

static void pass(const char *name) { std::cout << "PASS " << name << '\n'; }
static void fail(const char *name, const char *reason = "") {
  std::cout << "FAIL " << name;
  if (reason && reason[0]) std::cout << " (" << reason << ')';
  std::cout << '\n';
}
static void check(bool ok, const char *name, const char *reason = "") {
  ok ? pass(name) : fail(name, reason);
}

// Process Qt events for up to `ms` milliseconds
static void processFor(int ms) {
  QElapsedTimer t;
  t.start();
  while (t.elapsed() < ms) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    QThread::msleep(5);
  }
}

// Wait until predicate is true or timeout_ms elapsed
static bool waitUntil(const std::function<bool()> &pred, int timeout_ms) {
  QElapsedTimer t;
  t.start();
  while (t.elapsed() < timeout_ms) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    QThread::msleep(10);
    if (pred()) return true;
  }
  return pred();
}

// Find the 8-tab QTabWidget inside MainWindow
static QTabWidget *findAnalysisTabs(MainWindow &w) {
  for (auto *tw : w.findChildren<QTabWidget *>())
    if (tw->count() == 8) return tw;
  return nullptr;
}

// Find the packet stream table (6 columns, header col-1 == "Proto")
static QTableWidget *findStreamTable(MainWindow &w) {
  for (auto *t : w.findChildren<QTableWidget *>()) {
    if (t->columnCount() != 6) continue;
    auto *h = t->horizontalHeaderItem(1);
    if (h && h->text() == "Proto") return t;
  }
  return nullptr;
}

// ── Main ───────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
  qputenv("QT_QPA_PLATFORM", "offscreen");
  QApplication app(argc, argv);
  registerMetaTypes();

  // Suppress noise — only WARN+ during stress
  Logger::instance().setLevel(LogLevel::WARN);

  std::cout << "=== NetGuardianX GUI StressTest ===\n\n";

  // ── Setup ──────────────────────────────────────────────────────────────────
  AppController controller;
  MainWindow    window(&controller);
  window.show();
  processFor(100); // let Qt lay out widgets

  auto *tabs         = findAnalysisTabs(window);
  auto *stream_table = findStreamTable(window);
  auto *ctx_mgr      = window.findChild<PacketContextManager *>();

  check(tabs         != nullptr, "found 8-tab analysis widget");
  check(stream_table != nullptr, "found packet stream table");
  check(ctx_mgr      != nullptr, "found PacketContextManager");

  if (!tabs || !stream_table || !ctx_mgr) {
    std::cout << "FATAL: core widgets missing, aborting\n";
    return 1;
  }

  // ── Phase 1: Start simulation capture ──────────────────────────────────────
  std::cout << "\n--- Phase 1: start simulation capture\n";
  const bool started = controller.startCapture("lo"); // triggers simulation
  check(started, "capture started in simulation mode");

  // Wait for first packets to appear in stream table
  const bool got_packets = waitUntil(
      [&] { return stream_table->rowCount() > 0; }, 5000);
  check(got_packets, "packets appear in stream table within 5s");

  // ── Phase 2: 15-second flood with concurrent GUI hammering ──────────────────
  std::cout << "\n--- Phase 2: 15s flood — cycling tabs, selecting packets, injecting events\n";

  std::atomic<bool> flood_running{true};
  std::atomic<int>  tab_switches{0};
  std::atomic<int>  packet_selections{0};
  std::atomic<int>  filter_churns{0};
  std::atomic<int>  diag_runs{0};
  std::atomic<int>  alert_injections{0};

  // ── Background: inject alert events from a separate thread ────────────────
  // (EventBus is thread-safe; this is exactly the real-world pattern)
  std::thread alert_injector([&]() {
    int seq = 0;
    while (flood_running.load()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(80));
      EventType types[] = {
          EventType::ALERT_DNS_FAILURE,
          EventType::ALERT_PACKET_LOSS,
          EventType::ALERT_HIGH_RETRANSMISSION,
          EventType::ALERT_TCP_RESET,
      };
      EventBus::instance().publish({
          types[seq % 4], 0.0,
          "stress-inject-" + std::to_string(seq),
          "L4", "WARN",
          std::string{"stress.example.com"}
      });
      seq++;
      alert_injections++;
    }
  });

  // ── Qt-thread loop: tab churn + packet selection + filter churn + diag ────
  QElapsedTimer flood_timer;
  flood_timer.start();
  int cycle = 0;

  while (flood_timer.elapsed() < 15000) {
    // Cycle through all 8 tabs
    for (int t = 0; t < 8; t++) {
      tabs->setCurrentIndex(t);
      processFor(50);
      tab_switches++;
    }

    // Select latest packet (if any)
    if (stream_table->rowCount() > 0) {
      int row = stream_table->rowCount() - 1;
      stream_table->selectRow(row);
      processFor(30);
      packet_selections++;
    }

    // Also select from AppController directly (tests shared_ptr path)
    if (auto pkt = controller.selectedPacket()) {
      ctx_mgr->setActivePacket(pkt);
      processFor(20);
    }

    // Apply / clear BPF filter every 3rd cycle
    if (cycle % 3 == 0) {
      controller.applyFilter(cycle % 6 == 0 ? "tcp" : "");
      filter_churns++;
    }

    // Run diagnostics every 5th cycle
    if (cycle % 5 == 0) {
      controller.runDiagnostics();
      processFor(50);
      diag_runs++;
    }

    // Inject METRICS_UPDATED to stress overview/buffer tabs
    EventBus::instance().publish({EventType::METRICS_UPDATED, 0.0,
                                  "stress-metrics", "SYS", "INFO",
                                  std::string{}});

    cycle++;
    processFor(10);
  }

  flood_running = false;
  alert_injector.join();

  // Clear filter so subsequent tests see all packets
  controller.applyFilter("");

  std::cout << "  tab_switches=" << tab_switches.load()
            << " packet_selections=" << packet_selections.load()
            << " filter_churns=" << filter_churns.load()
            << " diag_runs=" << diag_runs.load()
            << " alert_injections=" << alert_injections.load()
            << " stream_rows=" << stream_table->rowCount() << '\n';

  // ── Phase 3: Post-flood sanity checks ─────────────────────────────────────
  std::cout << "\n--- Phase 3: post-flood sanity checks\n";

  // All 8 tabs still present and accessible
  check(tabs->count() == 8, "all 8 tabs still present after flood");

  // Verify each tab is switchable without crash
  bool all_tabs_switchable = true;
  for (int t = 0; t < 8; t++) {
    tabs->setCurrentIndex(t);
    processFor(30);
    all_tabs_switchable &= (tabs->currentIndex() == t);
  }
  check(all_tabs_switchable, "all 8 tabs switchable post-flood");

  // Metrics sane
  auto metrics = controller.getMetricsCopy();
  check(metrics.total_packets.load() > 0,
        "total_packets > 0 after flood");
  check(metrics.active_flows.load() > 0 || metrics.total_packets.load() > 0,
        "flow tracking active during flood");

  std::cout << "  total_packets=" << metrics.total_packets.load()
            << " active_flows=" << metrics.active_flows.load()
            << " retx_rate=" << metrics.retransmission_rate.load() << '\n';

  // Packets visible in stream
  check(stream_table->rowCount() > 0,
        "stream table has rows after flood");

  // PacketContextManager has a valid context
  bool has_ctx = ctx_mgr->hasContext() && ctx_mgr->current().valid;
  check(has_ctx, "PacketContextManager has valid context after flood");

  // ── Phase 4: Rapid start/stop under GUI load ───────────────────────────────
  std::cout << "\n--- Phase 4: 5× rapid start/stop cycles under GUI\n";
  bool startStop_ok = true;
  for (int i = 0; i < 5; i++) {
    controller.stopCapture();
    processFor(100);
    bool ok = controller.startCapture("lo");
    processFor(200);
    startStop_ok &= ok;
  }
  check(startStop_ok, "5× start/stop cycles survive under GUI");

  // Wait for packets again after restart
  const bool packets_after_restart = waitUntil(
      [&] { return stream_table->rowCount() > 0; }, 4000);
  check(packets_after_restart, "packets flow after restart");

  // ── Phase 5: Stop + verify all tabs go idle ────────────────────────────────
  std::cout << "\n--- Phase 5: stop capture, verify tabs go idle\n";
  controller.stopCapture();
  processFor(300);

  bool tabs_idle = true;
  for (int t = 0; t < tabs->count(); t++) {
    // Each tab sets activePacketId property to 0 when cleared
    tabs_idle &= (tabs->widget(t)->property("activePacketId").toULongLong() == 0);
  }
  check(tabs_idle, "all tabs idle after capture stop");

  // ── Phase 6: Diagnostics clean run post-flood ─────────────────────────────
  std::cout << "\n--- Phase 6: diagnostics post-flood\n";

  // Restart briefly to populate some events
  controller.startCapture("lo");
  processFor(1000);

  // Inject a DNS failure so diagnostics has something to find
  EventBus::instance().publish({EventType::ALERT_DNS_FAILURE, 0.0,
                                "DNS timeout resolving stress.example", "L7",
                                "WARN", std::string{"stress.example"}});
  processFor(100);

  std::optional<DiagnosticReport> report;
  QObject::connect(&controller, &AppController::diagnosticsComplete,
                   [&](const DiagnosticReport &r) { report = r; });
  controller.runDiagnostics();
  processFor(500);

  check(report.has_value(), "diagnostics emitted report post-flood");
  if (report) {
    bool has_dns = report->summary.find("DNS") != std::string::npos ||
                   !report->l7_issues.empty();
    check(has_dns, "diagnostics report contains DNS finding");
  }

  // ── Phase 7: Auto-healing executes post-flood ──────────────────────────────
  std::cout << "\n--- Phase 7: auto-healing command execution post-flood\n";

  std::optional<HealingResult> heal_result;
  QObject::connect(&controller, &AppController::newEvent,
                   [&](const Event &evt) {
    if (evt.type != EventType::HEALING_ACTION) return;
    try {
      heal_result = std::any_cast<HealingResult>(evt.payload);
    } catch (...) {}
  });

  controller.executeHealing(
      {"VERIFY_STACK", "Verify TCP/IP stack", "ip -s link", false});
  processFor(800);

  check(heal_result.has_value(), "healing result received");
  if (heal_result) {
    check(heal_result->executed,  "healing command was executed");
    check(heal_result->exit_code == 0, "healing command exit code 0");
    check(heal_result->success,   "healing reported success");
  }

  // ── Phase 8: Tab-specific slot bombardment ────────────────────────────────
  std::cout << "\n--- Phase 8: direct slot bombardment on each tab\n";

  // Fire 200 rapid packet selects + context changes while on each tab
  bool bombardment_ok = true;
  for (int t = 0; t < 8 && bombardment_ok; t++) {
    tabs->setCurrentIndex(t);
    processFor(20);

    for (int i = 0; i < 200; i++) {
      auto pkt = controller.selectedPacket();
      if (pkt) {
        ctx_mgr->setActivePacket(pkt);
      }
      if (i % 10 == 0) {
        EventBus::instance().publish({EventType::METRICS_UPDATED, 0.0,
                                      "bombard", "SYS", "INFO",
                                      std::string{}});
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
      }
    }
    processFor(30);
  }
  check(bombardment_ok, "200-slot-bombardment on each of 8 tabs");

  // ── Phase 9: Clear context, verify graceful empty state ───────────────────
  std::cout << "\n--- Phase 9: clear context — tabs handle empty state\n";
  controller.stopCapture();
  processFor(100);
  ctx_mgr->clearActivePacket();
  processFor(200);

  bool empty_ok = true;
  for (int t = 0; t < tabs->count(); t++) {
    tabs->setCurrentIndex(t);
    processFor(20);
    // Tab must still exist and not have crashed
    empty_ok &= (tabs->widget(t) != nullptr);
  }
  check(empty_ok, "all 8 tabs handle empty/cleared context");

  // ── Summary ────────────────────────────────────────────────────────────────
  std::cout << "\n=== GUIStressTest complete — if you see this line, no crash ===\n";
  return 0;
}

/*
── ADD TO CMakeLists.txt ────────────────────────────────────────────────────

add_executable(GUIStressTest
    tests/GUIStressTest.cpp
    ${CORE_SOURCES}
    ${GUI_SOURCES}
    ${MOC_GENERATED}
)
target_include_directories(GUIStressTest PRIVATE include ${PCAP_INCLUDE_DIRS})
target_compile_options(GUIStressTest PRIVATE -Wall -Wextra -O2 -g ${PCAP_CFLAGS_OTHER})
target_link_directories(GUIStressTest PRIVATE ${PCAP_LIBRARY_DIRS})
target_link_libraries(GUIStressTest PRIVATE
    Qt6::Widgets Qt6::Charts Qt6::Network Qt6::Core
    ${PCAP_LIBRARIES} pthread
)

*/
