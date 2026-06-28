#include "gui/tabs/EndToEndFlowTab.h"
#include "core/Logger.h"
#include "gui/PacketContextManager.h"
#include "gui/UiTheme.h"
#include <QAbstractItemView>
#include <QBrush>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QPainter>
#include <QPolygonF>
#include <QStringList>
#include <QVBoxLayout>
#include <QVariant>
#include <QVector>
#include <algorithm>
#include <any>
#include <cmath>

class TcpStateDiagramWidget : public QWidget {
public:
  explicit TcpStateDiagramWidget(QWidget *parent = nullptr) : QWidget(parent) {
    setMinimumWidth(360);
    setMinimumHeight(420);
  }

  void setFlow(const Flow *flow) {
    if (flow) {
      flow_ = *flow;
      has_flow_ = true;
      message_.clear();
    } else {
      has_flow_ = false;
    }
    update();
  }

  void setMessage(const QString &message, bool warning) {
    message_ = message;
    warning_ = warning;
    update();
  }

protected:
  void paintEvent(QPaintEvent *) override {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    p.fillRect(rect(), QColor(UiTheme::kBackground));

    QRectF bounds = rect().adjusted(18, 18, -18, -18);
    QFont title = font();
    title.setPointSize(12);
    title.setBold(true);
    p.setFont(title);
    p.setPen(QColor(UiTheme::kText));
    p.drawText(bounds.left(), bounds.top(), bounds.width(), 24,
               Qt::AlignLeft | Qt::AlignVCenter, "TCP State Diagram");

    if (!message_.isEmpty()) {
      p.setPen(warning_ ? QColor(UiTheme::kBad) : QColor(UiTheme::kMuted));
      p.drawText(QRectF(bounds.left(), bounds.top() + 30, bounds.width(), 42),
                 Qt::AlignLeft | Qt::TextWordWrap, message_);
    }

    if (!has_flow_) {
      p.setPen(QColor(UiTheme::kMuted));
      p.drawText(bounds.adjusted(0, 74, 0, 0), Qt::AlignTop | Qt::TextWordWrap,
                 "Select a flow to see its TCP state transitions.");
      return;
    }

    drawFlowSummary(p, bounds);
    drawStateGraph(p, bounds.adjusted(0, 92, 0, -70));
    drawHistory(
        p, QRectF(bounds.left(), bounds.bottom() - 58, bounds.width(), 58));
  }

private:
  struct Node {
    TCPState state;
    QPointF pos;
  };

  bool wasVisited(TCPState state) const {
    return std::any_of(
        flow_.state_history.begin(), flow_.state_history.end(),
        [state](const auto &item) { return item.second == state; });
  }

  void drawFlowSummary(QPainter &p, const QRectF &bounds) {
    QFont body = font();
    body.setPointSize(9);
    p.setFont(body);
    p.setPen(QColor(UiTheme::kMuted));
    const QString summary =
        QString("Flow %1  |  %2:%3 -> %4:%5  |  Current: %6")
            .arg(flow_.flow_id)
            .arg(QString::fromStdString(flow_.key.src_ip))
            .arg(flow_.key.src_port)
            .arg(QString::fromStdString(flow_.key.dst_ip))
            .arg(flow_.key.dst_port)
            .arg(QString::fromStdString(tcpStateToString(flow_.tcp_state)));
    p.drawText(QRectF(bounds.left(), bounds.top() + 32, bounds.width(), 44),
               Qt::AlignLeft | Qt::TextWordWrap, summary);
  }

  void drawStateGraph(QPainter &p, const QRectF &area) {
    const QVector<Node> nodes{
        {TCPState::CLOSED,
         QPointF(area.left() + area.width() * 0.50, area.top() + 28)},
        {TCPState::SYN_SENT, QPointF(area.left() + area.width() * 0.20,
                                     area.top() + area.height() * 0.30)},
        {TCPState::SYN_RECEIVED, QPointF(area.left() + area.width() * 0.80,
                                         area.top() + area.height() * 0.30)},
        {TCPState::ESTABLISHED, QPointF(area.left() + area.width() * 0.50,
                                        area.top() + area.height() * 0.52)},
        {TCPState::FIN_WAIT_1, QPointF(area.left() + area.width() * 0.22,
                                       area.top() + area.height() * 0.76)},
        {TCPState::TIME_WAIT, QPointF(area.left() + area.width() * 0.78,
                                      area.top() + area.height() * 0.76)}};

    auto nodeAt = [&](TCPState state) {
      for (const Node &node : nodes) {
        if (node.state == state) {
          return node.pos;
        }
      }
      return QPointF{};
    };

    auto drawArrow = [&](TCPState from, TCPState to) {
      QPointF a = nodeAt(from);
      QPointF b = nodeAt(to);
      if (a.isNull() || b.isNull()) {
        return;
      }
      const bool active = wasVisited(from) && wasVisited(to);
      p.setPen(QPen(active ? QColor(UiTheme::kTcp) : QColor(UiTheme::kBorder),
                    active ? 2 : 1));
      p.drawLine(a, b);
      const double angle = std::atan2(b.y() - a.y(), b.x() - a.x());
      const QPointF tip = a + (b - a) * 0.76;
      QPolygonF head;
      head << tip
           << QPointF(tip.x() - 8 * std::cos(angle - 0.5),
                      tip.y() - 8 * std::sin(angle - 0.5))
           << QPointF(tip.x() - 8 * std::cos(angle + 0.5),
                      tip.y() - 8 * std::sin(angle + 0.5));
      p.setBrush(active ? QColor(UiTheme::kTcp) : QColor(UiTheme::kBorder));
      p.drawPolygon(head);
    };

    drawArrow(TCPState::CLOSED, TCPState::SYN_SENT);
    drawArrow(TCPState::SYN_SENT, TCPState::SYN_RECEIVED);
    drawArrow(TCPState::SYN_RECEIVED, TCPState::ESTABLISHED);
    drawArrow(TCPState::ESTABLISHED, TCPState::FIN_WAIT_1);
    drawArrow(TCPState::FIN_WAIT_1, TCPState::TIME_WAIT);
    drawArrow(TCPState::TIME_WAIT, TCPState::CLOSED);

    for (const Node &node : nodes) {
      const bool current = node.state == flow_.tcp_state;
      const bool visited = wasVisited(node.state) || current;
      QRectF r(node.pos.x() - 58, node.pos.y() - 20, 116, 40);
      p.setPen(QPen(current   ? QColor(UiTheme::kText)
                    : visited ? QColor(UiTheme::kTcp)
                              : QColor(UiTheme::kBorder),
                    current ? 2 : 1));
      p.setBrush(current   ? QColor("#fbbf24")
                 : visited ? QColor("#2b3851")
                           : QColor(UiTheme::kPanel));
      p.drawRoundedRect(r, 7, 7);
      p.setPen(current ? QColor("#111827") : QColor(UiTheme::kText));
      QFont label = font();
      label.setPointSize(8);
      label.setBold(current);
      p.setFont(label);
      p.drawText(r.adjusted(4, 0, -4, 0), Qt::AlignCenter,
                 QString::fromStdString(tcpStateToString(node.state)));
    }
  }

  void drawHistory(QPainter &p, const QRectF &area) {
    QFont label = font();
    label.setPointSize(8);
    p.setFont(label);
    p.setPen(QColor(UiTheme::kMuted));

    QStringList parts;
    for (const auto &transition : flow_.state_history) {
      parts << QString::fromStdString(tcpStateToString(transition.second));
    }
    if (parts.isEmpty()) {
      parts << QString::fromStdString(tcpStateToString(flow_.tcp_state));
    }
    p.drawText(area, Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap,
               "History: " + parts.join(" -> "));
  }

  Flow flow_{};
  bool has_flow_{false};
  QString message_;
  bool warning_{false};
};

EndToEndFlowTab::EndToEndFlowTab(AppController *app_ctrl,
                                 PacketContextManager *ctx_mgr, QWidget *parent)
    : QWidget(parent), ctx_mgr_(ctx_mgr) {
  QVBoxLayout *root = new QVBoxLayout(this);
  context_label_ = new QLabel("Active packet: none selected. Click a flow or "
                              "packet to bind this view.");
  context_label_->setWordWrap(true);
  context_label_->setStyleSheet(
      QString("font-weight:700; color:%1; padding:8px; background:%2; "
              "border:1px solid %3; border-radius:8px;")
          .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
  root->addWidget(context_label_);

  QHBoxLayout *layout = new QHBoxLayout();
  flow_table_ = new QTableWidget(0, 6);
  flow_table_->setHorizontalHeaderLabels(
      {"Flow", "Source", "Destination", "Protocol", "Packets", "State"});
  flow_table_->horizontalHeader()->setStretchLastSection(true);
  flow_table_->setAlternatingRowColors(true);
  flow_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  flow_table_->setSelectionMode(QAbstractItemView::SingleSelection);
  state_diagram_ = new TcpStateDiagramWidget();
  layout->addWidget(flow_table_, 2);
  layout->addWidget(state_diagram_, 1);
  root->addLayout(layout, 1);

  connect(app_ctrl, &AppController::flowCreated, this,
          &EndToEndFlowTab::onFlowCreated);
  connect(app_ctrl, &AppController::flowUpdated, this,
          &EndToEndFlowTab::onFlowUpdated);
  connect(app_ctrl, &AppController::flowClosed, this,
          &EndToEndFlowTab::onFlowClosed);
  connect(app_ctrl, &AppController::alertTriggered, this,
          &EndToEndFlowTab::onAlert);
  connect(ctx_mgr_, &PacketContextManager::contextChanged, this,
          &EndToEndFlowTab::onContextChanged);

  connect(flow_table_, &QTableWidget::cellClicked, [this](int row, int) {
    auto *idItem = flow_table_->item(row, 0);
    if (!idItem)
      return;
    uint32_t id = idItem->text().toUInt();
    selectFlow(id);
    // Push the most-recent packet of this flow through the context manager
    auto it = flows_.find(id);
    if (it != flows_.end()) {
      ctx_mgr_->setActiveFlow(it->second);
    }
  });
  connect(flow_table_, &QTableWidget::cellDoubleClicked, [this](int row, int) {
    auto *idItem = flow_table_->item(row, 0);
    if (!idItem)
      return;
    const uint32_t id = idItem->text().toUInt();
    auto it = flows_.find(id);
    if (it != flows_.end())
      ctx_mgr_->setActiveFlow(it->second);
  });
}

int EndToEndFlowTab::rowForFlow(uint32_t flow_id) const {
  for (int row = 0; row < flow_table_->rowCount(); ++row) {
    auto *item = flow_table_->item(row, 0);
    if (item && item->text().toUInt() == flow_id)
      return row;
  }
  return -1;
}

void EndToEndFlowTab::upsertFlow(const Flow &flow) {
  flows_[flow.flow_id] = flow;
  if (selected_flow_id_ == 0) {
    selected_flow_id_ = flow.flow_id;
  }
  int row = rowForFlow(flow.flow_id);
  if (row < 0) {
    row = flow_table_->rowCount();
    flow_table_->insertRow(row);
  }
  flow_table_->setItem(row, 0,
                       new QTableWidgetItem(QString::number(flow.flow_id)));
  flow_table_->setItem(
      row, 1,
      new QTableWidgetItem(QString::fromStdString(flow.key.src_ip) + ":" +
                           QString::number(flow.key.src_port)));
  flow_table_->setItem(
      row, 2,
      new QTableWidgetItem(QString::fromStdString(flow.key.dst_ip) + ":" +
                           QString::number(flow.key.dst_port)));
  flow_table_->setItem(row, 3,
                       new QTableWidgetItem(QString::fromStdString(
                           protocolToString(flow.key.protocol))));
  flow_table_->setItem(
      row, 4, new QTableWidgetItem(QString::number(flow.stats.packet_count)));
  flow_table_->setItem(row, 5,
                       new QTableWidgetItem(QString::fromStdString(
                           tcpStateToString(flow.tcp_state))));
  if (selected_flow_id_ == flow.flow_id) {
    selectFlow(flow.flow_id);
  }
}

void EndToEndFlowTab::selectFlow(uint32_t flow_id) {
  selected_flow_id_ = flow_id;
  auto it = flows_.find(flow_id);
  state_diagram_->setFlow(it == flows_.end() ? nullptr : &it->second);
}

void EndToEndFlowTab::onContextChanged(PacketContext ctx) {
  if (!ctx.valid) {
    setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
    selected_flow_id_ = 0;
    flow_table_->clearSelection();
    context_label_->setText("Active packet: none selected. Click a flow or "
                            "packet to bind this view.");
    state_diagram_->setFlow(nullptr);
    return;
  }
  if (!ctx.valid || !ctx.packet)
    return;
  const UnifiedPacket &pkt = *ctx.packet;
  setProperty("activePacketId", QVariant::fromValue<qulonglong>(pkt.id));

  context_label_->setText(
      QString("▶  Packet #%1  |  Flow %2  |  %3:%4 → %5:%6  |  %7  |  %8 bytes")
          .arg(pkt.id)
          .arg(pkt.flow_id)
          .arg(QString::fromStdString(pkt.src_ip))
          .arg(pkt.src_port)
          .arg(QString::fromStdString(pkt.dst_ip))
          .arg(pkt.dst_port)
          .arg(QString::fromStdString(protocolToString(pkt.protocol)))
          .arg(pkt.packet_size));

  // Auto-select the matching flow and update TCP state diagram
  if (pkt.flow_id != 0 && flows_.find(pkt.flow_id) != flows_.end()) {
    selectFlow(pkt.flow_id);
    const int row = rowForFlow(pkt.flow_id);
    if (row >= 0)
      flow_table_->selectRow(row);
  }

  // If the context carries a resolved flow, update the diagram directly
  if (ctx.flow.has_value())
    state_diagram_->setFlow(&ctx.flow.value());
}

void EndToEndFlowTab::onFlowCreated(Flow flow) {
  Logger::instance().log(LogLevel::DEBUG, "GUI",
                         "EndToEndFlowTab slot called, updating widget");
  upsertFlow(flow);
}

void EndToEndFlowTab::onFlowUpdated(Flow flow) {
  Logger::instance().log(LogLevel::DEBUG, "GUI",
                         "EndToEndFlowTab slot called, updating widget");
  upsertFlow(flow);
}

void EndToEndFlowTab::onFlowClosed(uint32_t flow_id) {
  Logger::instance().log(LogLevel::DEBUG, "GUI",
                         "EndToEndFlowTab slot called, updating widget");
  auto it = flows_.find(flow_id);
  if (it != flows_.end()) {
    it->second.tcp_state = TCPState::CLOSED;
    it->second.is_active = false;
  }
  int row = rowForFlow(flow_id);
  if (row >= 0) {
    flow_table_->setItem(row, 5, new QTableWidgetItem("CLOSED"));
    for (int col = 0; col < flow_table_->columnCount(); ++col) {
      auto *item = flow_table_->item(row, col);
      if (item)
        item->setForeground(QBrush(Qt::gray));
    }
  }
  if (selected_flow_id_ == flow_id) {
    selectFlow(flow_id);
  }
}

void EndToEndFlowTab::onAlert(Event evt) {
  if (evt.type == EventType::ALERT_HIGH_RETRANSMISSION) {
    onRetransmissionDetected(evt);
  } else if (evt.type == EventType::ALERT_TCP_RESET) {
    onTCPReset(evt);
  }
}

void EndToEndFlowTab::onRetransmissionDetected(Event evt) {
  Logger::instance().log(LogLevel::DEBUG, "GUI",
                         "EndToEndFlowTab slot called, updating widget");
  try {
    uint32_t flow_id = std::any_cast<uint32_t>(evt.payload);

    int row = rowForFlow(flow_id);
    if (row >= 0) {
      auto *item = new QTableWidgetItem("HIGH RETRANSMIT");
      item->setForeground(QBrush(QColor(UiTheme::kBad)));
      flow_table_->setItem(row, 5, item);
    }

    if (flow_id == selected_flow_id_) {
      state_diagram_->setMessage("Warning: high retransmission detected.",
                                 true);
    }
  } catch (const std::bad_any_cast &) {
    // no-op: don't show generic warning anymore
  }
}

void EndToEndFlowTab::onTCPReset(Event evt) {
  Logger::instance().log(LogLevel::DEBUG, "GUI",
                         "EndToEndFlowTab slot called, updating widget");
  try {
    uint32_t flow_id = std::any_cast<uint32_t>(evt.payload);
    int row = rowForFlow(flow_id);
    if (row >= 0) {
      flow_table_->setItem(row, 5, new QTableWidgetItem("CLOSED (RST)"));
    }
    if (selected_flow_id_ == flow_id) {
      state_diagram_->setMessage("TCP reset detected on this flow.", true);
    }
  } catch (const std::bad_any_cast &) {
    state_diagram_->setMessage("TCP reset detected.", true);
  }
}
