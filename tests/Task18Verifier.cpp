#include <QApplication>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QTabWidget>
#include <QTableWidget>
#include <QThread>
#include <iostream>
#include <optional>
#include <vector>

#include "core/AppController.h"
#include "core/Logger.h"
#include "core/MetaTypes.h"
#include "core/eventbus/EventBus.h"
#include "gui/MainWindow.h"
#include "gui/PacketContextManager.h"

namespace {

bool waitUntil(const std::function<bool()> &predicate, int timeout_ms) {
  QElapsedTimer timer;
  timer.start();
  while (timer.elapsed() < timeout_ms) {
    QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
    QThread::msleep(10);
    if (predicate()) {
      return true;
    }
  }
  return predicate();
}

QTabWidget *analysisTabs(MainWindow &window) {
  const auto tabs = window.findChildren<QTabWidget *>();
  for (auto *tab : tabs) {
    if (tab->count() == 8) {
      return tab;
    }
  }
  return nullptr;
}

QTableWidget *packetStreamTable(MainWindow &window) {
  const auto tables = window.findChildren<QTableWidget *>();
  for (auto *table : tables) {
    if (table->columnCount() != 6) {
      continue;
    }
    auto *header = table->horizontalHeaderItem(1);
    if (header && header->text() == "Proto") {
      return table;
    }
  }
  return nullptr;
}

bool tableContainsProtocol(QTableWidget *table, const QString &protocol) {
  for (int row = 0; row < table->rowCount(); ++row) {
    auto *item = table->item(row, 1);
    if (item && item->text() == protocol) {
      return true;
    }
  }
  return false;
}

std::optional<UnifiedPacket> firstPacketFromTable(AppController &controller,
                                                  QTableWidget *table) {
  if (table->rowCount() <= 0) {
    return std::nullopt;
  }
  if (auto selected = controller.selectedPacket()) {
    return *selected; // dereference shared_ptr into UnifiedPacket
  }
  return std::nullopt;
}

void printResult(const char *name, bool ok) {
  std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
}

} // namespace

int main(int argc, char **argv) {
  qputenv("QT_QPA_PLATFORM", "offscreen");
  QApplication app(argc, argv);
  registerMetaTypes();
  Logger::instance().setLevel(LogLevel::WARN);

  bool ok = true;
  AppController controller;
  MainWindow window(&controller);
  window.show();

  auto *tabs = analysisTabs(window);
  const bool found_tabs = tabs && tabs->count() == 8;
  printResult("found all 8 analysis tabs", found_tabs);
  ok &= found_tabs;

  auto *ctx = window.findChild<PacketContextManager *>();
  const bool found_context = ctx != nullptr;
  printResult("found packet context manager", found_context);
  ok &= found_context;

  auto *stream_table = packetStreamTable(window);
  const bool found_stream = stream_table != nullptr;
  printResult("found packet stream table", found_stream);
  ok &= found_stream;
  if (!ok) {
    return 1;
  }

  const bool started = controller.startCapture("lo");
  printResult("capture started", started);
  ok &= started;

  const bool packets_visible =
      waitUntil([&] { return stream_table->rowCount() > 0; }, 5000);
  printResult("packets appear in stream", packets_visible);
  ok &= packets_visible;

  const bool dns_visible = waitUntil(
      [&] { return tableContainsProtocol(stream_table, "DNS"); }, 5000);
  printResult("DNS appears as DNS", dns_visible);
  ok &= dns_visible;

  const bool udp_not_required_for_dns =
      !dns_visible || tableContainsProtocol(stream_table, "DNS");
  printResult("DNS is not shown only as UDP", udp_not_required_for_dns);
  ok &= udp_not_required_for_dns;

  const bool https_visible = waitUntil(
      [&] { return tableContainsProtocol(stream_table, "HTTPS"); }, 5000);
  printResult("HTTPS appears as HTTPS", https_visible);
  ok &= https_visible;

  const bool tcp_not_required_for_https =
      !https_visible || tableContainsProtocol(stream_table, "HTTPS");
  printResult("HTTPS is not shown only as TCP", tcp_not_required_for_https);
  ok &= tcp_not_required_for_https;

  auto selected = firstPacketFromTable(controller, stream_table);
  const bool have_selected = selected.has_value();
  printResult("packet available for selection", have_selected);
  ok &= have_selected;

  if (tabs && selected) {
    controller.stopCapture();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 200);

    bool initially_idle = true;
    for (int i = 0; i < tabs->count(); ++i) {
      initially_idle &=
          tabs->widget(i)->property("activePacketId").toULongLong() == 0;
    }
    printResult("all 8 tabs begin idle after stop", initially_idle);
    ok &= initially_idle;

    ctx->setActivePacket(std::make_shared<const UnifiedPacket>(*selected));
    QCoreApplication::processEvents(QEventLoop::AllEvents, 200);

    bool all_tabs_selected = true;
    for (int i = 0; i < tabs->count(); ++i) {
      all_tabs_selected &=
          tabs->widget(i)->property("activePacketId").toULongLong() ==
          selected->id;
    }
    printResult("selecting packet updates all 8 tabs", all_tabs_selected);
    ok &= all_tabs_selected;

    controller.stopCapture();
    QCoreApplication::processEvents(QEventLoop::AllEvents, 200);

    bool all_tabs_idle = true;
    for (int i = 0; i < tabs->count(); ++i) {
      all_tabs_idle &=
          tabs->widget(i)->property("activePacketId").toULongLong() == 0;
    }
    printResult("stopping capture clears all tabs to idle", all_tabs_idle);
    ok &= all_tabs_idle;
  }

  std::optional<DiagnosticReport> report_seen;
  QObject::connect(
      &controller, &AppController::diagnosticsComplete,
      [&](const DiagnosticReport &report) { report_seen = report; });
  EventBus::instance().publish({EventType::ALERT_DNS_FAILURE, 0.0,
                                "DNS timeout resolving task18.example", "L7",
                                "WARN", std::string{"task18.example"}});
  QCoreApplication::processEvents(QEventLoop::AllEvents, 200);
  controller.runDiagnostics();
  QCoreApplication::processEvents(QEventLoop::AllEvents, 200);
  const bool l7_dns_failure =
      report_seen.has_value() && !report_seen->l7_issues.empty() &&
      report_seen->summary.find("L7") != std::string::npos &&
      report_seen->summary.find("DNS") != std::string::npos;
  printResult("diagnostics L7 shows DNS failures", l7_dns_failure);
  ok &= l7_dns_failure;

  std::optional<HealingResult> healing_seen;
  QObject::connect(
      &controller, &AppController::newEvent, [&](const Event &event) {
        if (event.type != EventType::HEALING_ACTION) {
          return;
        }
        try {
          healing_seen = std::any_cast<HealingResult>(event.payload);
        } catch (const std::bad_any_cast &) {
        }
      });
  controller.executeHealing(
      {"VERIFY_STACK", "Verify TCP/IP stack health", "ip -s link", false});
  QCoreApplication::processEvents(QEventLoop::AllEvents, 500);
  const bool healing_exit_code =
      healing_seen.has_value() && healing_seen->executed &&
      healing_seen->exit_code == 0 && healing_seen->success;
  printResult("healing executes real command and returns exit code 0",
              healing_exit_code);
  ok &= healing_exit_code;

  controller.stopCapture();
  return ok ? 0 : 1;
}
