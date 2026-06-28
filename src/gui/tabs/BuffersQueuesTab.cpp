#include "gui/tabs/BuffersQueuesTab.h"
#include "core/Logger.h"
#include "gui/UiTheme.h"
#include <QFontDatabase>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QSplitter>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>
#include <algorithm>
#include <cmath>
#include <deque>

// ═══════════════════════════════════════════════════════════════════════════
//  GaugeBar  – sleek horizontal fill-bar with glow effect
// ═══════════════════════════════════════════════════════════════════════════
class GaugeBar : public QWidget {
public:
  explicit GaugeBar(const QString &label, QWidget *parent = nullptr)
      : QWidget(parent), label_(label) {
    setFixedHeight(56);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  }

  void setValue(double pct, uint64_t raw) {
    pct_ = std::clamp(pct, 0.0, 100.0);
    raw_ = raw;
    update();
  }

protected:
  void paintEvent(QPaintEvent *) override {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    // Card background with subtle gradient
    QLinearGradient bg(0, 0, 0, height());
    bg.setColorAt(0, QColor("#131f35"));
    bg.setColorAt(1, QColor("#0d1828"));
    p.fillRect(rect(), bg);

    // Left accent stripe
    QColor accentCol = pct_ > 80   ? QColor(UiTheme::kBad)
                       : pct_ > 50 ? QColor(UiTheme::kWarn)
                                   : QColor(UiTheme::kAccent);
    p.setPen(Qt::NoPen);
    p.setBrush(accentCol);
    p.drawRoundedRect(QRectF(0, 6, 3, height() - 12), 2, 2);

    QRectF r(14, 4, rect().width() - 22, rect().height() - 8);

    // Label
    QFont lf = font();
    lf.setPointSize(8);
    lf.setBold(true);
    p.setFont(lf);
    p.setPen(QColor(UiTheme::kMuted));
    p.drawText(QRectF(r.left(), r.top(), r.width(), 16),
               Qt::AlignLeft | Qt::AlignVCenter, label_.toUpper());

    // Value
    QFont vf = font();
    vf.setPointSize(9);
    vf.setBold(true);
    p.setFont(vf);
    p.setPen(accentCol);
    p.drawText(QRectF(r.left(), r.top(), r.width(), 16),
               Qt::AlignRight | Qt::AlignVCenter,
               QString("%1%").arg(pct_, 0, 'f', 1));

    // Bar track
    QRectF bar(r.left(), r.top() + 22, r.width(), 14);
    p.setPen(Qt::NoPen);
    p.setBrush(QColor("#0a1220"));
    p.drawRoundedRect(bar, 7, 7);

    // Fill with glow
    double fillW = bar.width() * pct_ / 100.0;
    if (fillW > 2) {
      QLinearGradient grad(bar.left(), 0, bar.left() + fillW, 0);
      grad.setColorAt(0, accentCol.darker(150));
      grad.setColorAt(0.6, accentCol);
      grad.setColorAt(1, accentCol.lighter(130));
      p.setBrush(grad);
      p.drawRoundedRect(QRectF(bar.left(), bar.top(), fillW, bar.height()), 7,
                        7);

      // Glow effect
      QColor glow = accentCol;
      glow.setAlpha(40);
      p.setBrush(glow);
      p.drawRoundedRect(
          QRectF(bar.left(), bar.top() - 2, fillW, bar.height() + 4), 7, 7);
    }

    // 80% threshold marker
    double tx = bar.left() + bar.width() * 0.80;
    p.setPen(QPen(QColor(UiTheme::kBad).lighter(120), 1, Qt::DashLine));
    p.drawLine(QPointF(tx, bar.top() - 3), QPointF(tx, bar.bottom() + 3));

    // Raw value below
    QFont sf = font();
    sf.setPointSize(7);
    p.setFont(sf);
    p.setPen(QColor(UiTheme::kMuted));
    p.drawText(QRectF(r.left(), bar.bottom() + 2, r.width(), 12),
               Qt::AlignLeft | Qt::AlignVCenter, QString("raw: %1").arg(raw_));
  }

private:
  QString label_;
  double pct_{0};
  uint64_t raw_{0};
};

// ═══════════════════════════════════════════════════════════════════════════
//  FlowCanvas  – animated pipeline visualization
// ═══════════════════════════════════════════════════════════════════════════
class FlowCanvas : public QWidget {
public:
  explicit FlowCanvas(QWidget *parent = nullptr) : QWidget(parent) {
    setMinimumHeight(170);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    anim_timer_ = new QTimer(this);
    anim_timer_->setInterval(40); // 25 fps
    connect(anim_timer_, &QTimer::timeout, this, [this] {
      phase_ = std::fmod(phase_ + speed_, 1.0);
      update();
    });
    anim_timer_->start();
  }

  void setRates(double rxPps, double txPps, uint64_t rxDrops,
                uint64_t txDrops) {
    rx_pps_ = rxPps;
    tx_pps_ = txPps;
    rx_drops_ = rxDrops;
    tx_drops_ = txDrops;
    speed_ = std::clamp(rxPps / 60.0, 0.008, 0.06);
  }

  void highlightPacket(const UnifiedPacket &pkt) {
    highlight_proto_ = QString::fromStdString(protocolToString(pkt.protocol));
    highlight_size_ = pkt.packet_size;
    highlight_flow_ = pkt.flow_id;
  }

  void clearHighlight() {
    highlight_proto_ = "—";
    highlight_size_ = 0;
    highlight_flow_ = 0;
    update();
  }

protected:
  void paintEvent(QPaintEvent *) override {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    // Dark background with grid
    p.fillRect(rect(), QColor("#080f1c"));
    p.setPen(QPen(QColor("#0e1a2e"), 1));
    for (int x = 0; x < width(); x += 40)
      p.drawLine(x, 0, x, height());
    for (int y = 0; y < height(); y += 20)
      p.drawLine(0, y, width(), y);

    struct Stage {
      QString label;
      QColor border;
      QColor bg;
    };
    const Stage stages[] = {
        {"WIRE", QColor("#a78bfa"), QColor("#1a1040")},
        {"RX RING", QColor("#60a5fa"), QColor("#0f1e35")},
        {"SOCKET", QColor("#f59e0b"), QColor("#1f1508")},
        {"TX RING", QColor("#2dd4bf"), QColor("#081a18")},
        {"WIRE", QColor("#a78bfa"), QColor("#1a1040")},
    };
    constexpr int N = 5;
    const double stageW = (rect().width() - 32.0) / N;
    const double stageH = 48;
    const double stageY = (rect().height() - stageH) / 2.0;

    // Pipeline connector tube
    double tubeY = stageY + stageH / 2 - 5;
    QLinearGradient tubeGrad(12, 0, rect().width() - 20, 0);
    tubeGrad.setColorAt(0, QColor("#1a2a40"));
    tubeGrad.setColorAt(0.5, QColor("#1e3050"));
    tubeGrad.setColorAt(1, QColor("#1a2a40"));
    p.setBrush(tubeGrad);
    p.setPen(QPen(QColor("#25344d"), 1));
    p.drawRoundedRect(QRectF(12, tubeY, rect().width() - 24, 10), 5, 5);

    // Stage boxes
    for (int i = 0; i < N; ++i) {
      double x = 16 + stageW * i;
      QRectF box(x + 2, stageY, stageW - 4, stageH);

      // Glow behind box
      QColor glow = stages[i].border;
      glow.setAlpha(30);
      p.setPen(Qt::NoPen);
      p.setBrush(glow);
      p.drawRoundedRect(box.adjusted(-3, -3, 3, 3), 10, 10);

      // Box
      p.setBrush(stages[i].bg);
      p.setPen(QPen(stages[i].border, 1));
      p.drawRoundedRect(box, 8, 8);

      // Label
      QFont f = font();
      f.setPointSize(7);
      f.setBold(true);
      p.setFont(f);
      p.setPen(stages[i].border);
      p.drawText(box, Qt::AlignCenter, stages[i].label);
    }

    double totalW = rect().width() - 28.0;
    const double rxY = stageY - 26;
    const double txY = stageY + stageH + 10;

    // Lane labels
    QFont lf = font();
    lf.setPointSize(7);
    lf.setBold(true);
    p.setFont(lf);
    p.setPen(QColor(UiTheme::kGood));
    p.drawText(QRectF(14, rxY - 2, 40, 12), Qt::AlignLeft, "▶ RX");
    p.setPen(QColor(UiTheme::kTcp));
    p.drawText(QRectF(14, txY + 2, 40, 12), Qt::AlignLeft, "◀ TX");

    // RX packets (left → right) — green
    for (int pk = 0; pk < 5; ++pk) {
      double pos = std::fmod(phase_ + pk * 0.2, 1.0);
      double x = 14 + pos * totalW;
      QColor pc = QColor(UiTheme::kGood);
      // Glow
      QRadialGradient g(x, rxY + 4, 12);
      g.setColorAt(0, pc);
      g.setColorAt(1, Qt::transparent);
      p.setPen(Qt::NoPen);
      p.setBrush(g);
      p.drawEllipse(QPointF(x, rxY + 4), 12, 6);
      // Packet
      p.setBrush(pc);
      p.drawRoundedRect(QRectF(x - 8, rxY, 16, 10), 3, 3);
    }

    // TX packets (right → left) — amber
    for (int pk = 0; pk < 4; ++pk) {
      double pos = std::fmod(1.0 - phase_ + pk * 0.25, 1.0);
      double x = 14 + pos * totalW;
      QColor pc = QColor(UiTheme::kTcp);
      QRadialGradient g(x, txY + 4, 12);
      g.setColorAt(0, pc);
      g.setColorAt(1, Qt::transparent);
      p.setPen(Qt::NoPen);
      p.setBrush(g);
      p.drawEllipse(QPointF(x, txY + 4), 12, 6);
      p.setBrush(pc);
      p.drawRoundedRect(QRectF(x - 8, txY, 16, 10), 3, 3);
    }

    // Drop indicator
    if (rx_drops_ > 0 || tx_drops_ > 0) {
      double dropX = 16 + stageW * 1 + stageW * 0.5;
      p.setPen(QPen(QColor(UiTheme::kBad), 2));
      QFont df = font();
      df.setPointSize(8);
      df.setBold(true);
      p.setFont(df);
      p.drawText(QRectF(dropX - 30, stageY - 44, 60, 14), Qt::AlignCenter,
                 QString("✕ %1 drops").arg(rx_drops_ + tx_drops_));
    }

    // Footer stats
    p.setPen(QColor(UiTheme::kMuted));
    QFont sf = font();
    sf.setPointSize(8);
    p.setFont(sf);
    p.drawText(QRectF(14, rect().height() - 18, rect().width() - 28, 16),
               Qt::AlignLeft | Qt::AlignVCenter,
               QString("RX %1 pps  ·  TX %2 pps  ·  drops %3  ·  proto %4  ·  "
                       "flow %5  ·  %6 B")
                   .arg(rx_pps_, 0, 'f', 0)
                   .arg(tx_pps_, 0, 'f', 0)
                   .arg(rx_drops_ + tx_drops_)
                   .arg(highlight_proto_)
                   .arg(highlight_flow_)
                   .arg(highlight_size_));
  }

private:
  QTimer *anim_timer_{nullptr};
  double phase_{0.0}, speed_{0.02};
  double rx_pps_{0}, tx_pps_{0};
  uint64_t rx_drops_{0}, tx_drops_{0};
  QString highlight_proto_{"—"};
  uint16_t highlight_size_{0};
  uint32_t highlight_flow_{0};
};

// ═══════════════════════════════════════════════════════════════════════════
//  HistoryChart  – rolling multi-line chart — FIXED to use real PPS data
// ═══════════════════════════════════════════════════════════════════════════
class HistoryChart : public QWidget {
public:
  explicit HistoryChart(QWidget *parent = nullptr) : QWidget(parent) {
    setMinimumHeight(130);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
  }

  // FIX: takes actual PPS values not always-zero drop percentages
  void addSample(double pps, double rxDropPct, double sockPct) {
    pps_.push_back(pps);
    if ((int)pps_.size() > kMaxPts)
      pps_.pop_front();
    rx_.push_back(rxDropPct);
    if ((int)rx_.size() > kMaxPts)
      rx_.pop_front();
    sock_.push_back(sockPct);
    if ((int)sock_.size() > kMaxPts)
      sock_.pop_front();
    update();
  }

protected:
  void paintEvent(QPaintEvent *) override {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    // Background
    QLinearGradient bg(0, 0, 0, height());
    bg.setColorAt(0, QColor("#0c1828"));
    bg.setColorAt(1, QColor("#080f1c"));
    p.fillRect(rect(), bg);
    p.setPen(QPen(QColor(UiTheme::kBorder), 1));
    p.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 8, 8);

    QRectF g = QRectF(rect()).adjusted(48, 10, -12, -26);

    // Grid lines + Y labels
    QFont f = font();
    f.setPointSize(7);
    p.setFont(f);
    for (int i = 0; i <= 4; ++i) {
      double y = g.bottom() - g.height() * i / 4.0;
      p.setPen(QColor(UiTheme::kMuted));
      p.drawText(QRectF(4, y - 7, 42, 14), Qt::AlignRight | Qt::AlignVCenter,
                 QString("%1%").arg(i * 25));
      p.setPen(QPen(QColor("#1a2a40"), 1, Qt::DotLine));
      p.drawLine(QPointF(g.left(), y), QPointF(g.right(), y));
    }

    if (pps_.empty()) {
      p.setPen(QColor(UiTheme::kMuted));
      QFont wf = font();
      wf.setPointSize(9);
      wf.setItalic(true);
      p.setFont(wf);
      p.drawText(g, Qt::AlignCenter, "Waiting for traffic...");
      return;
    }

    // Normalize PPS to 0-100 scale using rolling max
    double maxPps = *std::max_element(pps_.begin(), pps_.end());
    if (maxPps < 1.0)
      maxPps = 1.0;

    auto drawSeries = [&](const std::deque<double> &data, double scale,
                          const QColor &col, bool filled) {
      if (data.size() < 2)
        return;
      QPainterPath path, fillPath;
      bool first = true;
      for (int i = 0; i < (int)data.size(); ++i) {
        double x = g.left() + (double)i / (kMaxPts - 1) * g.width();
        double y = g.bottom() - (data[i] / scale) * g.height();
        y = std::clamp(y, g.top(), g.bottom());
        if (first) {
          path.moveTo(x, y);
          fillPath.moveTo(x, g.bottom());
          fillPath.lineTo(x, y);
          first = false;
        } else {
          path.lineTo(x, y);
          fillPath.lineTo(x, y);
        }
      }
      if (filled) {
        fillPath.lineTo(g.left() + (double)(data.size() - 1) / (kMaxPts - 1) *
                                       g.width(),
                        g.bottom());
        fillPath.closeSubpath();
        QColor fc = col;
        fc.setAlpha(25);
        p.setPen(Qt::NoPen);
        p.setBrush(fc);
        p.drawPath(fillPath);
      }
      p.setPen(QPen(col, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
      p.setBrush(Qt::NoBrush);
      p.drawPath(path);
      // End dot
      double lx =
          g.left() + (double)(data.size() - 1) / (kMaxPts - 1) * g.width();
      double ly = g.bottom() - (data.back() / scale) * g.height();
      ly = std::clamp(ly, g.top(), g.bottom());
      p.setPen(Qt::NoPen);
      p.setBrush(col);
      p.drawEllipse(QPointF(lx, ly), 3.5, 3.5);
    };

    drawSeries(pps_, maxPps, QColor(UiTheme::kAccent), true);
    drawSeries(rx_, 100.0, QColor(UiTheme::kBad), false);
    drawSeries(sock_, 100.0, QColor(UiTheme::kPayload), false);

    // Legend
    struct {
      const char *label;
      const char *color;
    } legend[] = {
        {"PPS (scaled)", UiTheme::kAccent},
        {"RX drops %", UiTheme::kBad},
        {"Sock buf %", UiTheme::kPayload},
    };
    double lx = g.left();
    QFont lf2 = font();
    lf2.setPointSize(7);
    p.setFont(lf2);
    for (auto &l : legend) {
      p.setPen(Qt::NoPen);
      p.setBrush(QColor(l.color));
      p.drawRoundedRect(QRectF(lx, rect().bottom() - 18, 8, 8), 2, 2);
      p.setPen(QColor(UiTheme::kMuted));
      p.drawText(QRectF(lx + 11, rect().bottom() - 19, 82, 12),
                 Qt::AlignLeft | Qt::AlignVCenter, l.label);
      lx += 94;
    }
  }

private:
  static constexpr int kMaxPts = 60;
  std::deque<double> pps_, rx_, sock_;
};

// ═══════════════════════════════════════════════════════════════════════════
//  BuffersQueuesTab
// ═══════════════════════════════════════════════════════════════════════════

BuffersQueuesTab::BuffersQueuesTab(AppController *app_ctrl,
                                   PacketContextManager *ctx_mgr,
                                   QWidget *parent)
    : QWidget(parent) {
  auto *root = new QVBoxLayout(this);
  root->setContentsMargins(12, 12, 12, 12);
  root->setSpacing(10);

  // ── Active packet banner ───────────────────────────────────────────────
  selected_packet_label_ =
      new QLabel("Select a packet in the stream to see its queue journey.");
  selected_packet_label_->setWordWrap(true);
  selected_packet_label_->setStyleSheet(
      QString("font-weight:700; font-size:9pt; color:%1; padding:10px 14px;"
              "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 "
              "#0f1e35,stop:1 #091624);"
              "border-left: 3px solid %1; border-radius:6px;")
          .arg(UiTheme::kAccent));
  root->addWidget(selected_packet_label_);

  // ── Gauge row ─────────────────────────────────────────────────────────
  auto *gaugeRow = new QHBoxLayout();
  gaugeRow->setSpacing(8);
  rx_gauge_ = new GaugeBar("NIC RX Ring fill");
  tx_gauge_ = new GaugeBar("NIC TX Ring fill");
  sock_gauge_ = new GaugeBar("Socket Buffer fill");
  gaugeRow->addWidget(rx_gauge_);
  gaugeRow->addWidget(tx_gauge_);
  gaugeRow->addWidget(sock_gauge_);
  root->addLayout(gaugeRow);

  // ── Flow animation ────────────────────────────────────────────────────
  flow_canvas_ = new FlowCanvas();
  root->addWidget(flow_canvas_);

  // ── History chart ──────────────────────────────────────────────────────
  auto *chartLabel = new QLabel("  BUFFER HISTORY  —  last 60 seconds");
  chartLabel->setStyleSheet(
      QString("color:%1; font-weight:800; font-size:8pt; letter-spacing:1px;"
              "padding:4px 8px; background:%2; border-radius:4px;")
          .arg(UiTheme::kMuted, UiTheme::kPanelAlt));
  root->addWidget(chartLabel);
  history_chart_ = new HistoryChart();
  root->addWidget(history_chart_);

  root->addStretch(1);

  // ── Poll real data every 1s ─────────────────────────────────────────────
  auto *poll = new QTimer(this);
  connect(poll, &QTimer::timeout, this, [this, app_ctrl] {
    auto snap = app_ctrl->getBufferMonitor().snapshot();
    auto metrics = app_ctrl->getMetricsCopy();

    constexpr uint64_t kRingCap = 4096;
    constexpr uint64_t kSockCap = 212992;

    double rxPct = std::min(100.0, 100.0 * snap.nic_rx_dropped / kRingCap);
    double txPct = std::min(100.0, 100.0 * snap.nic_tx_dropped / kRingCap);
    double sockPct =
        std::min(100.0, 100.0 * snap.socket_buffer_usage / kSockCap);

    rx_gauge_->setValue(rxPct, snap.nic_rx_dropped);
    tx_gauge_->setValue(txPct, snap.nic_tx_dropped);
    sock_gauge_->setValue(sockPct, snap.socket_buffer_usage);

    double pps = (double)metrics.packets_per_second.load();
    flow_canvas_->setRates(pps, pps * 0.6, snap.nic_rx_dropped,
                           snap.nic_tx_dropped);

    // FIX: pass actual PPS so graph always shows real data
    history_chart_->addSample(pps, rxPct, sockPct);
  });
  poll->start(1000);

  connect(app_ctrl, &AppController::alertTriggered, this,
          &BuffersQueuesTab::onDropDetected);
  connect(app_ctrl, &AppController::selectedPacketChanged, this,
          &BuffersQueuesTab::onSelectedPacket);
  connect(ctx_mgr, &PacketContextManager::contextChanged, this,
          &BuffersQueuesTab::onContextChanged);
}

void BuffersQueuesTab::onDropDetected(Event evt) {
  if (evt.type != EventType::ALERT_PACKET_LOSS)
    return;
  rx_gauge_->setValue(100, 0);
  tx_gauge_->setValue(100, 0);
  selected_packet_label_->setText(
      "⚠  Packet loss detected — RX ring overflow. "
      "Increase ring size with: ethtool -G <iface> rx 4096");
  selected_packet_label_->setStyleSheet(
      QString("font-weight:700; font-size:9pt; color:%1; padding:10px 14px;"
              "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 "
              "#2a0f0f,stop:1 #1a0808);"
              "border-left: 3px solid %1; border-radius:6px;")
          .arg(UiTheme::kBad));
}

void BuffersQueuesTab::onSelectedPacket(
    std::shared_ptr<const UnifiedPacket> pkt) {
  if (!pkt)
    return;
  const UnifiedPacket &pk = *pkt;
  QString journey;
  if (pk.has_tcp && (pk.tcp_flags & 0x04))
    journey = "RST — bypassed socket buffer (rejected at TCP layer)";
  else if (pk.has_tcp && (pk.tcp_flags & 0x02))
    journey = "SYN — enqueued in SYN backlog → accept queue on SYN-ACK";
  else if (pk.has_dns)
    journey =
        "DNS/UDP — short-lived socket buffer, reclaimed after resolver reads";
  else if (pk.has_http)
    journey = "HTTP/TCP — held in socket recv buffer until application read()";
  else if (pk.has_icmp)
    journey =
        "ICMP — kernel processed, does not enter application socket buffer";
  else
    journey =
        "TCP data — enters socket recv buffer, drained by application recv()";

  selected_packet_label_->setText(
      QString("▶  Packet #%1  ·  %2 B total  ·  %3 B payload  ·  flow %4\n"
              "   %5")
          .arg(pk.id)
          .arg(pk.packet_size)
          .arg(pk.payload_len)
          .arg(pk.flow_id)
          .arg(journey));
  selected_packet_label_->setStyleSheet(
      QString("font-weight:700; font-size:9pt; color:%1; padding:10px 14px;"
              "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 "
              "#0f1e35,stop:1 #091624);"
              "border-left: 3px solid %1; border-radius:6px;")
          .arg(UiTheme::kAccent));
  flow_canvas_->highlightPacket(pk);
}

void BuffersQueuesTab::onContextChanged(PacketContext ctx) {
  if (ctx.valid && ctx.packet) {
    setProperty("activePacketId",
                QVariant::fromValue<qulonglong>(ctx.packet->id));
    onSelectedPacket(ctx.packet);
    return;
  }
  setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
  selected_packet_label_->setText(
      "Select a packet in the stream to see its queue journey.");
  selected_packet_label_->setStyleSheet(
      QString("font-weight:700; font-size:9pt; color:%1; padding:10px 14px;"
              "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 "
              "#0f1e35,stop:1 #091624);"
              "border-left: 3px solid %1; border-radius:6px;")
          .arg(UiTheme::kAccent));
  flow_canvas_->clearHighlight();
}