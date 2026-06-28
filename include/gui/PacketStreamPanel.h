#include <memory>
#pragma once
#include "core/AppController.h"
#include "gui/PacketContextManager.h"
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTimer>
#include <QWidget>
#include <deque>

class PacketStreamPanel : public QWidget {
  Q_OBJECT
public:
  explicit PacketStreamPanel(AppController *app_ctrl,
                             PacketContextManager *ctx_mgr,
                             QWidget *parent = nullptr);
public slots:
  void onPacketReceived(std::shared_ptr<const UnifiedPacket> pkt);
  void onContextChanged(PacketContext ctx);

private slots:
  void flushPending();

private:
  void selectRow(int row);
  void applyFilter();
  void applyFilterToRow(int row, const QString &rawFilter = {});
  void addRowToTable(const UnifiedPacket &pkt);
  QColor rowColor(const UnifiedPacket &pkt) const;

  QTimer *flush_timer_{nullptr};
  std::deque<std::shared_ptr<const UnifiedPacket>> pending_;

  QTableWidget *table_{nullptr};
  QLineEdit *filter_edit_{nullptr};
  QPushButton *pause_btn_{nullptr};
  QPushButton *clear_btn_{nullptr};
  QLabel *counter_label_{nullptr};

  AppController *app_ctrl_{nullptr};
  PacketContextManager *ctx_mgr_{nullptr};

  std::deque<std::shared_ptr<const UnifiedPacket>> packets_;
  bool paused_{false};
  int active_row_{-1};
  static constexpr int kMaxRows = 2000;
};