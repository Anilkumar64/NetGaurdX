#pragma once
#include <QMainWindow>
#include <QTabWidget>
#include <QLabel>
#include <QComboBox>
#include <QPushButton>
#include <QLineEdit>
#include <QSplitter>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"
#include "gui/PacketStreamPanel.h"
#include "gui/tabs/NetworkOverviewTab.h"
#include "gui/tabs/DiagnosticsTab.h"
#include "gui/tabs/TCPIPVisualizerTab.h"
#include "gui/tabs/PacketDeepDiveTab.h"
#include "gui/tabs/EndToEndFlowTab.h"
#include "gui/tabs/BuffersQueuesTab.h"
#include "gui/tabs/NICPhysicalTab.h"
#include "gui/tabs/AutoHealingTab.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(AppController *app_ctrl, QWidget *parent = nullptr);
    void closeEvent(QCloseEvent *event) override;

public slots:
    void onCaptureStateChanged(QString mode);
    void onMetricsUpdated(NetworkMetrics metrics);
    void onNewEvent(Event evt);

private:
    AppController        *app_ctrl_{nullptr};
    PacketContextManager *ctx_mgr_{nullptr};

    // Layout
    QSplitter            *main_splitter_{nullptr};
    PacketStreamPanel    *stream_panel_{nullptr};
    QTabWidget           *right_tabs_{nullptr};

    // Status bar labels
    QLabel *status_mode_label_{nullptr};
    QLabel *status_interface_label_{nullptr};
    QLabel *status_packets_label_{nullptr};
    QLabel *status_flows_label_{nullptr};

    // Toolbar
    QComboBox   *interface_combo_{nullptr};
    QLineEdit   *bpf_filter_edit_{nullptr};
    QPushButton *start_btn_{nullptr};
    QPushButton *stop_btn_{nullptr};
};
