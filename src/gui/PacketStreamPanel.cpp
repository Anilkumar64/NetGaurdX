#include "gui/PacketStreamPanel.h"
#include "core/Logger.h"
#include "gui/UiTheme.h"
#include <QFont>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QScrollBar>
#include <QVBoxLayout>

PacketStreamPanel::PacketStreamPanel(AppController *app_ctrl,
                                     PacketContextManager *ctx_mgr,
                                     QWidget *parent)
    : QWidget(parent), app_ctrl_(app_ctrl), ctx_mgr_(ctx_mgr) {
  setMinimumWidth(320);
  auto *root = new QVBoxLayout(this);
  root->setContentsMargins(0, 0, 0, 0);
  root->setSpacing(0);

  // ── Header ────────────────────────────────────────────────────────────────
  auto *header = new QLabel("  Live Packet Stream");
  header->setStyleSheet(
      QString("font-weight:800; font-size:10pt; color:%1;"
              "background:%2; border-bottom:1px solid %3; padding:10px 8px;")
          .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
  root->addWidget(header);

  // ── Controls ──────────────────────────────────────────────────────────────
  auto *ctrl = new QHBoxLayout();
  ctrl->setContentsMargins(6, 6, 6, 4);
  ctrl->setSpacing(4);

  filter_edit_ = new QLineEdit();
  filter_edit_->setPlaceholderText(
      "protocol == TCP  |  src == 10.0.0.5  |  port == 80");
  filter_edit_->setStyleSheet(
      QString("background:%1; color:%2; border:1px solid %3; "
              "border-radius:4px; padding:4px 6px; font-size:8pt;")
          .arg(UiTheme::kPanelAlt, UiTheme::kText, UiTheme::kBorder));

  pause_btn_ = new QPushButton("⏸");
  pause_btn_->setFixedWidth(34);
  pause_btn_->setFixedHeight(26);
  pause_btn_->setToolTip("Pause / Resume stream");

  clear_btn_ = new QPushButton("✕");
  clear_btn_->setFixedWidth(34);
  clear_btn_->setFixedHeight(26);
  clear_btn_->setToolTip("Clear stream");

  ctrl->addWidget(filter_edit_, 1);
  ctrl->addWidget(pause_btn_);
  ctrl->addWidget(clear_btn_);
  root->addLayout(ctrl);

  // ── Counter bar ───────────────────────────────────────────────────────────
  counter_label_ = new QLabel("0 packets  |  click any row to select");
  counter_label_->setStyleSheet(
      QString("color:%1; font-size:8pt; padding:2px 8px 4px 8px;")
          .arg(UiTheme::kMuted));
  root->addWidget(counter_label_);

  // ── Table ─────────────────────────────────────────────────────────────────
  table_ = new QTableWidget(0, 6);
  table_->setHorizontalHeaderLabels(
      {"#", "Proto", "Source IP", "Dest IP", "Ports", "B"});
  table_->horizontalHeader()->setStretchLastSection(false);
  table_->horizontalHeader()->setSectionResizeMode(
      0, QHeaderView::ResizeToContents);
  table_->horizontalHeader()->setSectionResizeMode(
      1, QHeaderView::ResizeToContents);
  table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  table_->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
  table_->horizontalHeader()->setSectionResizeMode(
      4, QHeaderView::ResizeToContents);
  table_->horizontalHeader()->setSectionResizeMode(
      5, QHeaderView::ResizeToContents);
  table_->setAlternatingRowColors(true);
  table_->setSelectionBehavior(QAbstractItemView::SelectRows);
  table_->setSelectionMode(QAbstractItemView::SingleSelection);
  table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
  table_->setShowGrid(false);
  table_->verticalHeader()->hide();
  table_->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);

  QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
  mono.setPointSize(8);
  table_->setFont(mono);
  table_->verticalHeader()->setDefaultSectionSize(20); // compact rows

  table_->setStyleSheet(QString("QTableWidget { border:none; }"
                                "QTableWidget::item { padding:2px 4px; }"
                                "QTableWidget::item:selected { background:%1; "
                                "color:#06101f; font-weight:bold; }")
                            .arg(UiTheme::kAccent));
  root->addWidget(table_, 1);

  // ── Connections ──────────────────────────────────────────────────────────
  connect(pause_btn_, &QPushButton::clicked, this, [this] {
    paused_ = !paused_;
    pause_btn_->setText(paused_ ? "▶" : "⏸");
    pause_btn_->setStyleSheet(
        paused_ ? QString("background:%1; color:#06101f; border-radius:4px;")
                      .arg(UiTheme::kWarn)
                : "");
    counter_label_->setText(QString("%1 packets  |  %2")
                                .arg(packets_.size())
                                .arg(paused_ ? "PAUSED — scroll freely"
                                             : "click any row to select"));
  });

  connect(clear_btn_, &QPushButton::clicked, this, [this] {
    packets_.clear();
    table_->setRowCount(0);
    active_row_ = -1;
    counter_label_->setText("0 packets  |  stream cleared");
  });

  connect(filter_edit_, &QLineEdit::textChanged, this,
          &PacketStreamPanel::applyFilter);

  connect(table_, &QTableWidget::cellClicked, this,
          [this](int row, int) { selectRow(row); });

  connect(app_ctrl_, &AppController::packetReceived, this,
          &PacketStreamPanel::onPacketReceived);
  connect(ctx_mgr_, &PacketContextManager::contextChanged, this,
          &PacketStreamPanel::onContextChanged);

  flush_timer_ = new QTimer(this);
  flush_timer_->setInterval(200);
  connect(flush_timer_, &QTimer::timeout, this,
          &PacketStreamPanel::flushPending);
  flush_timer_->start();
}

void PacketStreamPanel::onPacketReceived(
    std::shared_ptr<const UnifiedPacket> pkt) {
  if (!pkt)
    return;

  packets_.push_back(pkt);
  if ((int)packets_.size() > kMaxRows)
    packets_.pop_front();

  if (!paused_)
    pending_.push_back(pkt);
}

void PacketStreamPanel::addRowToTable(const UnifiedPacket &pkt) {
  int row = table_->rowCount();
  table_->insertRow(row);

  auto makeItem = [](const QString &text) {
    auto *item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
  };

  table_->setItem(row, 0, makeItem(QString::number(pkt.id)));
  table_->setItem(
      row, 1, makeItem(QString::fromStdString(protocolToString(pkt.protocol))));
  table_->setItem(row, 2, makeItem(QString::fromStdString(pkt.src_ip)));
  table_->setItem(row, 3, makeItem(QString::fromStdString(pkt.dst_ip)));
  table_->setItem(
      row, 4, makeItem(QString("%1→%2").arg(pkt.src_port).arg(pkt.dst_port)));
  table_->setItem(row, 5, makeItem(QString::number(pkt.packet_size)));

  // Color code
  QColor bg = rowColor(pkt);
  if (bg.isValid())
    for (int c = 0; c < 6; ++c)
      if (table_->item(row, c))
        table_->item(row, c)->setBackground(bg);

  applyFilterToRow(row);
}

void PacketStreamPanel::flushPending() {
  if (pending_.empty())
    return;

  constexpr int kMaxPerFlush = 50;
  int count = std::min((int)pending_.size(), kMaxPerFlush);

  table_->setUpdatesEnabled(false);
  for (int i = 0; i < count; ++i) {
    if (table_->rowCount() >= kMaxRows)
      table_->removeRow(0);
    addRowToTable(*pending_.front());
    pending_.pop_front();
  }
  table_->setUpdatesEnabled(true);

  if (active_row_ < 0 || active_row_ >= table_->rowCount() - 5)
    table_->scrollToBottom();

  counter_label_->setText(
      QString("%1 packets  |  click any row to select").arg(packets_.size()));
}

void PacketStreamPanel::onContextChanged(PacketContext ctx) {
  if (!ctx.valid) {
    packets_.clear();
    table_->setRowCount(0);
    active_row_ = -1;
    table_->clearSelection();
    counter_label_->setText("0 packets  |  idle");
    return;
  }

  // Find and highlight the row — but DON'T auto-scroll if user is paused
  for (int row = 0; row < table_->rowCount(); ++row) {
    auto *item = table_->item(row, 0);
    // BUG1-FIX: ctx.packet is now shared_ptr, dereference for id
    if (item && ctx.packet && item->text().toULongLong() == ctx.packet->id) {
      active_row_ = row;
      // Block signals to prevent cellClicked re-entering
      table_->blockSignals(true);
      table_->selectRow(row);
      table_->blockSignals(false);
      if (!paused_)
        table_->scrollToItem(item, QAbstractItemView::EnsureVisible);
      return;
    }
  }
}

void PacketStreamPanel::selectRow(int row) {
  if (row < 0 || row >= (int)packets_.size())
    return;
  active_row_ = row;

  // Find the packet — table rows may not 1:1 map to packets_ if rows were
  // cleared Use the ID from the table cell to find the right packet
  auto *idItem = table_->item(row, 0);
  if (!idItem)
    return;
  uint64_t id = idItem->text().toULongLong();

  for (auto &p : packets_) {
    // BUG1-FIX: p is shared_ptr — compare via ->, pass directly to
    // setActivePacket
    if (p && p->id == id) {
      ctx_mgr_->setActivePacket(p);
      return;
    }
  }
}

void PacketStreamPanel::applyFilter() {
  const QString raw = filter_edit_->text().trimmed().toLower();
  for (int row = 0; row < table_->rowCount(); ++row)
    applyFilterToRow(row, raw);
}

void PacketStreamPanel::applyFilterToRow(int row, const QString &rawFilter) {
  const QString raw = rawFilter.isEmpty()
                          ? filter_edit_->text().trimmed().toLower()
                          : rawFilter;

  bool hide = false;
  if (!raw.isEmpty()) {
    bool matched = false;
    if (raw.contains("protocol") && raw.contains("==")) {
      QString proto = raw.section("==", 1).trimmed().toUpper();
      auto *item = table_->item(row, 1);
      matched = item && item->text().toUpper() == proto;
    } else if (raw.contains("src") && raw.contains("==")) {
      QString src = raw.section("==", 1).trimmed();
      auto *item = table_->item(row, 2);
      matched = item && item->text().contains(src);
    } else if (raw.contains("dst") && raw.contains("==")) {
      QString dst = raw.section("==", 1).trimmed();
      auto *item = table_->item(row, 3);
      matched = item && item->text().contains(dst);
    } else if (raw.contains("port") && raw.contains("==")) {
      QString port = raw.section("==", 1).trimmed();
      auto *item = table_->item(row, 4);
      matched = item && item->text().contains(port);
    } else {
      // Free text: any column
      for (int c = 0; c < 6 && !matched; ++c) {
        auto *item = table_->item(row, c);
        if (item && item->text().toLower().contains(raw))
          matched = true;
      }
    }
    hide = !matched;
  }
  table_->setRowHidden(row, hide);
}

QColor PacketStreamPanel::rowColor(const UnifiedPacket &pkt) const {
  if (pkt.has_tcp && (pkt.tcp_flags & 0x04))
    return QColor(UiTheme::kBad).darker(160); // RST
  if (pkt.has_tcp && (pkt.tcp_flags & 0x12) == 0x12)
    return QColor(UiTheme::kGood).darker(210); // SYN-ACK
  if (pkt.has_tcp && (pkt.tcp_flags & 0x02))
    return QColor(UiTheme::kGood).darker(230); // SYN
  if (pkt.protocol == Protocol::QUIC)
    return QColor(UiTheme::kGood).darker(230);
  if (pkt.has_http)
    return QColor(UiTheme::kPayload).darker(260);
  if (pkt.has_dns)
    return QColor(UiTheme::kWarn).darker(260);
  if (pkt.has_icmp)
    return QColor(UiTheme::kIp).darker(280);
  return QColor(); // alternating default
}
