#include "gui/tabs/DiagnosticsTab.h"
#include "core/Logger.h"
#include "gui/PacketContextManager.h"
#include "gui/UiTheme.h"
#include <QDateTime>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QPainter>
#include <QPainterPath>
#include <QScrollBar>
#include <QSplitter>
#include <QStringList>
#include <QVBoxLayout>
#include <QVariant>

// ═══════════════════════════════════════════════════════════════════════════
//  RootCausePanel  –  painted widget showing layer findings
// ═══════════════════════════════════════════════════════════════════════════

class RootCausePanel : public QWidget {
public:
  struct Finding {
    QString layer;    // "L2" / "L3" / "L4" / "L7" / "SYS"
    QString severity; // "INFO" / "WARN" / "CRIT"
    QString title;
    QString explanation;
    QString recommendation;
  };

  explicit RootCausePanel(QWidget *parent = nullptr) : QWidget(parent) {
    setMinimumHeight(200);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
  }

  void setFindings(const std::vector<Finding> &findings) {
    findings_ = findings;
    updateGeometry();
    update();
  }

  void clear() {
    findings_.clear();
    update();
  }

protected:
  QSize sizeHint() const override {
    int h = findings_.empty() ? 60 : (int)findings_.size() * 58 + 16;
    return {400, std::max(h, 200)};
  }

  void paintEvent(QPaintEvent *) override {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.fillRect(rect(), QColor(UiTheme::kPanel));
    p.setPen(QPen(QColor(UiTheme::kBorder), 1));
    p.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 8, 8);

    if (findings_.empty()) {
      p.setPen(QColor(UiTheme::kMuted));
      QFont f = font();
      f.setItalic(true);
      p.setFont(f);
      p.drawText(rect().adjusted(16, 0, -16, 0), Qt::AlignVCenter,
                 "Select a packet in the stream → layer analysis appears here");
      return;
    }

    int y = 12;
    for (auto &f : findings_) {
      if (y + 50 > rect().height())
        break;

      QColor sevColor = (f.severity == "CRIT")   ? QColor(UiTheme::kBad)
                        : (f.severity == "WARN") ? QColor(UiTheme::kWarn)
                                                 : QColor(UiTheme::kGood);

      // Left accent bar
      p.setPen(Qt::NoPen);
      p.setBrush(sevColor);
      p.drawRoundedRect(QRectF(8, y, 3, 44), 1, 1);

      // Layer badge
      p.setBrush(sevColor.darker(130));
      p.drawRoundedRect(QRectF(18, y + 2, 32, 18), 4, 4);
      QFont badge = font();
      badge.setPointSize(7);
      badge.setBold(true);
      p.setFont(badge);
      p.setPen(QColor("#06101f"));
      p.drawText(QRectF(18, y + 2, 32, 18), Qt::AlignCenter, f.layer);

      // Severity dot
      p.setPen(Qt::NoPen);
      p.setBrush(sevColor);
      p.drawEllipse(QPointF(58, y + 11), 5, 5);

      // Title
      QFont title = font();
      title.setBold(true);
      title.setPointSize(9);
      p.setFont(title);
      p.setPen(QColor(UiTheme::kText));
      p.drawText(QRectF(70, y, rect().width() - 82, 20), Qt::AlignVCenter,
                 f.title);

      // Explanation
      QFont body = font();
      body.setPointSize(8);
      p.setFont(body);
      p.setPen(QColor(UiTheme::kMuted));
      p.drawText(QRectF(70, y + 20, rect().width() - 82, 16), Qt::AlignVCenter,
                 f.explanation);

      // Recommendation
      if (!f.recommendation.isEmpty()) {
        p.setPen(QColor(UiTheme::kAccent));
        p.drawText(QRectF(70, y + 36, rect().width() - 82, 14),
                   Qt::AlignVCenter, "→ " + f.recommendation);
        y += 54;
      } else {
        y += 42;
      }

      // Divider
      p.setPen(QPen(QColor(UiTheme::kBorder), 1));
      p.drawLine(QPointF(14, y + 2), QPointF(rect().width() - 14, y + 2));
      y += 8;
    }
  }

private:
  std::vector<Finding> findings_;
};

// ═══════════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════════

namespace {

QString evtTypeName(EventType t) {
  switch (t) {
  case EventType::FLOW_CREATED:
    return "FLOW_CREATED";
  case EventType::FLOW_UPDATED:
    return "FLOW_UPDATED";
  case EventType::FLOW_CLOSED:
    return "FLOW_CLOSED";
  case EventType::ALERT_DNS_FAILURE:
    return "DNS_FAILURE";
  case EventType::ALERT_PACKET_LOSS:
    return "PACKET_LOSS";
  case EventType::ALERT_HIGH_RETRANSMISSION:
    return "HIGH_RETX";
  case EventType::ALERT_TCP_RESET:
    return "TCP_RESET";
  case EventType::HEALING_ACTION:
    return "HEALING";
  case EventType::CAPTURE_STARTED:
    return "CAPTURE_START";
  case EventType::CAPTURE_STOPPED:
    return "CAPTURE_STOP";
  case EventType::INTERFACE_CHANGED:
    return "IFACE_CHANGE";
  default:
    return "EVENT";
  }
}

bool isAlertEvent(EventType t) {
  return t == EventType::ALERT_DNS_FAILURE ||
         t == EventType::ALERT_PACKET_LOSS ||
         t == EventType::ALERT_HIGH_RETRANSMISSION ||
         t == EventType::ALERT_TCP_RESET;
}

bool isNoiseEvent(EventType t) {
  // Never show these in the event log — far too frequent
  return t == EventType::PACKET_CAPTURED || t == EventType::FLOW_UPDATED ||
         t == EventType::METRICS_UPDATED;
}

QString tcpFlagMeaning(uint8_t flags) {
  QStringList parts;
  if (flags & 0x02)
    parts << "SYN";
  if (flags & 0x10)
    parts << "ACK";
  if (flags & 0x04)
    parts << "RST";
  if (flags & 0x01)
    parts << "FIN";
  if (flags & 0x08)
    parts << "PSH";
  if (flags & 0x20)
    parts << "URG";
  return parts.isEmpty() ? "—" : parts.join("|");
}

std::vector<RootCausePanel::Finding> analyzePacket(const UnifiedPacket &pkt) {
  std::vector<RootCausePanel::Finding> findings;

  // ── L2 Ethernet ────────────────────────────────────────────────────────
  if (pkt.has_eth) {
    findings.push_back({"L2", "INFO", "Ethernet frame decoded",
                        QString("Frame %1 B, ethertype 0x%2")
                            .arg(pkt.packet_size)
                            .arg(pkt.eth_hdr.ethertype, 4, 16, QChar('0')),
                        ""});
  }

  // ── L3 IP ──────────────────────────────────────────────────────────────
  if (pkt.has_ip) {
    QString sev = "INFO", rec;
    if (pkt.ip_hdr.ttl < 5) {
      sev = "WARN";
      rec = "TTL near zero — check for routing loops or excessive hops";
    }
    findings.push_back({"L3", sev,
                        QString("IPv4  %1 → %2  TTL=%3")
                            .arg(QString::fromStdString(pkt.src_ip))
                            .arg(QString::fromStdString(pkt.dst_ip))
                            .arg(pkt.ip_hdr.ttl),
                        QString("Total %1 B,  proto field %2")
                            .arg(pkt.ip_hdr.total_length)
                            .arg(pkt.ip_hdr.protocol),
                        rec});
  }

  // ── L4 TCP ─────────────────────────────────────────────────────────────
  if (pkt.has_tcp) {
    uint8_t f = pkt.tcp_flags;
    bool rst = f & 0x04, syn = f & 0x02, fin = f & 0x01, ack = f & 0x10;

    if (rst) {
      findings.push_back({"L4", "CRIT", "TCP RST — connection aborted",
                          QString("Port %1→%2  Seq %3")
                              .arg(pkt.src_port)
                              .arg(pkt.dst_port)
                              .arg(pkt.seq_num),
                          "Check if dst port is open, inspect firewall rules, "
                          "or if app crashed"});
    } else if (syn && !ack) {
      findings.push_back({"L4", "INFO", "TCP SYN — new connection initiating",
                          QString("Port %1→%2  Seq %3")
                              .arg(pkt.src_port)
                              .arg(pkt.dst_port)
                              .arg(pkt.seq_num),
                          "Expect SYN-ACK within ~100ms; if absent, dst is "
                          "unreachable or refusing"});
    } else if (syn && ack) {
      findings.push_back({"L4", "INFO", "TCP SYN-ACK — handshake response",
                          QString("Port %1←%2  Seq %3 Ack %4")
                              .arg(pkt.dst_port)
                              .arg(pkt.src_port)
                              .arg(pkt.seq_num)
                              .arg(pkt.ack_num),
                          ""});
    } else if (fin) {
      findings.push_back(
          {"L4", "INFO", "TCP FIN — graceful close",
           QString("Port %1→%2  flags [%3]")
               .arg(pkt.src_port)
               .arg(pkt.dst_port)
               .arg(tcpFlagMeaning(f)),
           "Normal close sequence; expect FIN-ACK from the other side"});
    } else {
      QString note = pkt.payload_len == 0
                         ? "ACK-only / keepalive — no payload"
                         : QString("Payload %1 B").arg(pkt.payload_len);
      findings.push_back({"L4", "INFO",
                          QString("TCP data  port %1→%2  [%3]")
                              .arg(pkt.src_port)
                              .arg(pkt.dst_port)
                              .arg(tcpFlagMeaning(f)),
                          QString("Seq %1  Ack %2  %3")
                              .arg(pkt.seq_num)
                              .arg(pkt.ack_num)
                              .arg(note),
                          ""});
    }
  } else if (pkt.has_udp) {
    findings.push_back(
        {"L4", "INFO",
         QString("UDP  port %1→%2").arg(pkt.src_port).arg(pkt.dst_port),
         QString(
             "Length %1 B, payload %2 B — connectionless, no retransmission")
             .arg(pkt.udp_hdr.length)
             .arg(pkt.payload_len),
         ""});
  } else if (pkt.has_icmp) {
    findings.push_back({"L4", "INFO",
                        QString("ICMP type %1 code %2")
                            .arg(pkt.icmp_hdr.type)
                            .arg(pkt.icmp_hdr.code),
                        pkt.icmp_hdr.type == 8   ? "Echo request (ping)"
                        : pkt.icmp_hdr.type == 0 ? "Echo reply (pong)"
                                                 : "ICMP control message",
                        ""});
  }

  // ── L7 DNS ─────────────────────────────────────────────────────────────
  if (pkt.has_dns) {
    bool hasAnswer = !pkt.dns_info.answers.empty();
    findings.push_back(
        {"L7", hasAnswer ? "INFO" : "WARN",
         hasAnswer ? "DNS resolved" : "DNS query — no answer yet",
         QString("Query: %1  %2")
             .arg(QString::fromStdString(pkt.dns_info.query_name))
             .arg(hasAnswer ? "→ " + QString::fromStdString(
                                         pkt.dns_info.answers.front())
                            : "(waiting for response)"),
         hasAnswer ? "" : "If no response arrives, check resolver at dst IP"});
  }

  // ── L7 HTTP ────────────────────────────────────────────────────────────
  if (pkt.has_http) {
    QString code = QString::fromStdString(pkt.http_info.status_code);
    bool isErr = !code.isEmpty() && (code[0] == '4' || code[0] == '5');
    QString desc = !pkt.http_info.method.empty()
                       ? QString::fromStdString(pkt.http_info.method) + " " +
                             QString::fromStdString(pkt.http_info.url)
                       : "HTTP response " + code;
    findings.push_back(
        {"L7", isErr ? "WARN" : "INFO",
         QString("HTTP ") +
             (pkt.http_info.method.empty() ? "response" : "request"),
         desc,
         isErr ? "HTTP " + code + " — inspect body for server error details"
               : ""});
  }

  return findings;
}

void appendReportIssues(std::vector<RootCausePanel::Finding> &findings,
                        const QString &layer,
                        const std::vector<std::string> &issues) {
  for (const auto &issue : issues) {
    findings.push_back({layer, "WARN",
                        QString("%1 diagnostic finding").arg(layer),
                        QString::fromStdString(issue),
                        "Review related packets and recent event log entries"});
  }
}

std::vector<RootCausePanel::Finding>
findingsFromReport(const DiagnosticReport &report) {
  std::vector<RootCausePanel::Finding> findings;
  appendReportIssues(findings, "L2", report.l2_issues);
  appendReportIssues(findings, "L3", report.l3_issues);
  appendReportIssues(findings, "L4", report.l4_issues);
  appendReportIssues(findings, "L7", report.l7_issues);

  if (findings.empty()) {
    findings.push_back(
        {"SYS", report.is_healthy ? "INFO" : "WARN",
         report.is_healthy ? "No active root causes found"
                           : "Diagnostics completed",
         QString::fromStdString(report.summary),
         report.is_healthy
             ? ""
             : "Inspect the system event log for supporting evidence"});
  }

  return findings;
}

void addEventRow(QTableWidget *table, const QString &time, const QString &type,
                 const QString &layer, const QString &desc,
                 const QColor &rowColor = {}) {
  int row = table->rowCount();
  table->insertRow(row);
  table->setItem(row, 0, new QTableWidgetItem(time));
  table->setItem(row, 1, new QTableWidgetItem(type));
  table->setItem(row, 2, new QTableWidgetItem(layer));
  table->setItem(row, 3, new QTableWidgetItem(desc));
  if (rowColor.isValid())
    for (int c = 0; c < 4; ++c)
      if (table->item(row, c))
        table->item(row, c)->setBackground(rowColor);
  // Keep max 300 rows
  while (table->rowCount() > 300)
    table->removeRow(0);
  table->scrollToBottom();
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
//  DiagnosticsTab
// ═══════════════════════════════════════════════════════════════════════════

DiagnosticsTab::DiagnosticsTab(AppController *app_ctrl,
                               PacketContextManager *ctx_mgr, QWidget *parent)
    : QWidget(parent), app_ctrl_(app_ctrl) {
  auto *root = new QVBoxLayout(this);
  root->setContentsMargins(10, 10, 10, 10);
  root->setSpacing(8);

  // ── Status banner ──────────────────────────────────────────────────────
  auto *topRow = new QHBoxLayout();
  health_summary_ = new QLabel(
      "Select a packet in the stream to see layer-by-layer diagnosis.");
  health_summary_->setWordWrap(true);
  health_summary_->setStyleSheet(
      QString("font-weight:700; color:%1; padding:10px;"
              "background:%2; border:1px solid %3; border-radius:8px;")
          .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
  run_diag_btn_ = new QPushButton("▶  Run Full Diagnostics");
  topRow->addWidget(health_summary_, 1);
  topRow->addWidget(run_diag_btn_);
  root->addLayout(topRow);

  // ── Splitter: top = analysis, bottom = event log ───────────────────────
  auto *splitter = new QSplitter(Qt::Vertical);
  root->addWidget(splitter, 1);

  // ── Top: root cause panel ─────────────────────────────────────────────
  auto *analysisWidget = new QWidget();
  auto *analysisLayout = new QVBoxLayout(analysisWidget);
  analysisLayout->setContentsMargins(0, 0, 0, 0);
  analysisLayout->setSpacing(6);

  root_cause_header_ = new QLabel("Layer-by-layer analysis");
  root_cause_header_->setStyleSheet(
      QString("color:%1; font-weight:700; font-size:9pt;")
          .arg(UiTheme::kMuted));
  analysisLayout->addWidget(root_cause_header_);

  root_cause_panel_ = new RootCausePanel();
  analysisLayout->addWidget(root_cause_panel_, 1);
  splitter->addWidget(analysisWidget);

  // ── Bottom: event log table ────────────────────────────────────────────
  auto *logWidget = new QWidget();
  auto *logLayout = new QVBoxLayout(logWidget);
  logLayout->setContentsMargins(0, 0, 0, 0);
  logLayout->setSpacing(4);

  auto *logTitle =
      new QLabel("System event log  (flow lifecycle, alerts, diagnostics)");
  logTitle->setStyleSheet(QString("color:%1; font-weight:700; font-size:9pt;")
                              .arg(UiTheme::kMuted));
  logLayout->addWidget(logTitle);

  event_table_ = new QTableWidget(0, 4);
  event_table_->setHorizontalHeaderLabels(
      {"Time", "Event", "Layer", "Description"});
  event_table_->horizontalHeader()->setStretchLastSection(true);
  event_table_->horizontalHeader()->setSectionResizeMode(
      0, QHeaderView::ResizeToContents);
  event_table_->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::ResizeToContents);
  event_table_->horizontalHeader()->setSectionResizeMode(
      2, QHeaderView::ResizeToContents);
  event_table_->setAlternatingRowColors(true);
  event_table_->setSortingEnabled(false);
  event_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  event_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  logLayout->addWidget(event_table_, 1);
  splitter->addWidget(logWidget);

  splitter->setStretchFactor(0, 6);
  splitter->setStretchFactor(1, 4);

  // ── Connections ────────────────────────────────────────────────────────
  connect(run_diag_btn_, &QPushButton::clicked,
          [this] { app_ctrl_->runDiagnostics(); });
  connect(app_ctrl_, &AppController::newEvent, this,
          &DiagnosticsTab::onNewEvent);
  connect(app_ctrl_, &AppController::alertTriggered, this,
          &DiagnosticsTab::onAlert);
  connect(app_ctrl_, &AppController::diagnosticsComplete, this,
          &DiagnosticsTab::onDiagnosticsComplete);
  connect(ctx_mgr, &PacketContextManager::contextChanged, this,
          &DiagnosticsTab::onContextChanged);
}

void DiagnosticsTab::onNewEvent(Event evt) {
  // Filter out high-frequency noise
  if (isNoiseEvent(evt.type))
    return;

  QString ts = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
  QString type = evtTypeName(evt.type);
  QString desc = QString::fromStdString(evt.description);
  addEventRow(event_table_, ts, type, QString::fromStdString(evt.layer), desc);
}

void DiagnosticsTab::onAlert(Event evt) {
  if (!isAlertEvent(evt.type))
    return;

  QString ts = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
  QString type = evtTypeName(evt.type);
  QString desc = QString::fromStdString(evt.description);

  addEventRow(event_table_, ts, "⚠ " + type, "ALERT", desc,
              QColor(UiTheme::kBad).darker(170));

  health_summary_->setText("⚠  Alert: " + desc);
  health_summary_->setStyleSheet(
      QString("font-weight:700; color:%1; padding:10px;"
              "background:%2; border:1px solid %1; border-radius:8px;")
          .arg(UiTheme::kBad, UiTheme::kPanel));
}

void DiagnosticsTab::onDiagnosticsComplete(DiagnosticReport report) {
  health_summary_->setText(
      report.is_healthy ? "✓  System healthy — no active root causes found"
                        : "⚠  Issue detected — see analysis below");

  const char *color = report.is_healthy ? UiTheme::kGood : UiTheme::kWarn;
  health_summary_->setStyleSheet(
      QString("font-weight:700; color:%1; padding:10px;"
              "background:%2; border:1px solid %1; border-radius:8px;")
          .arg(color, UiTheme::kPanel));

  root_cause_header_->setText("Global root cause analysis");
  root_cause_panel_->setFindings(findingsFromReport(report));

  QString ts = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
  addEventRow(event_table_, ts, "DIAGNOSTICS", "SYS",
              report.is_healthy ? "Healthy — no issues found"
                                : QString::fromStdString(report.summary));
}

void DiagnosticsTab::onContextChanged(PacketContext ctx) {
  if (!ctx.valid) {
    setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
    health_summary_->setText(
        "Select a packet in the stream to see layer-by-layer diagnosis.");
    health_summary_->setStyleSheet(
        QString("font-weight:700; color:%1; padding:10px;"
                "background:%2; border:1px solid %3; border-radius:8px;")
            .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
    root_cause_header_->setText("Layer-by-layer analysis");
    root_cause_panel_->clear();
    return;
  }

  if (!ctx.valid || !ctx.packet)
    return;
  const UnifiedPacket &pkt = *ctx.packet;
  setProperty("activePacketId", QVariant::fromValue<qulonglong>(pkt.id));

  // Update banner
  QString flowInfo;
  if (ctx.flow.has_value()) {
    const auto &fl = *ctx.flow;
    flowInfo = QString("  |  retx %1  RTT %2 ms  state %3")
                   .arg(fl.stats.retransmissions)
                   .arg(fl.stats.rtt_ms, 0, 'f', 1)
                   .arg(QString::fromStdString(tcpStateToString(fl.tcp_state)));
  }
  health_summary_->setText(
      QString("Analyzing packet #%1  |  flow %2  |  %3%4")
          .arg(pkt.id)
          .arg(pkt.flow_id)
          .arg(QString::fromStdString(protocolToString(pkt.protocol)))
          .arg(flowInfo));
  health_summary_->setStyleSheet(
      QString("font-weight:700; color:%1; padding:10px;"
              "background:%2; border:1px solid %3; border-radius:8px;")
          .arg(UiTheme::kAccent, UiTheme::kPanel, UiTheme::kBorder));

  root_cause_header_->setText(
      QString("Packet #%1 root cause analysis").arg(pkt.id));

  // Rebuild root cause panel
  auto findings = analyzePacket(pkt);
  root_cause_panel_->setFindings(findings);
}
