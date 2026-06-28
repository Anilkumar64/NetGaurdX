#include "gui/MainWindow.h"
#include <QStatusBar>
#include <QToolBar>
#include <QVBoxLayout>
#include <QCloseEvent>
#include <QMessageBox>
#include <any>
#include "core/Logger.h"
#include "gui/UiTheme.h"

MainWindow::MainWindow(AppController *app_ctrl, QWidget *parent)
    : QMainWindow(parent), app_ctrl_(app_ctrl)
{
    setWindowTitle("NetGuardian X");
    resize(1520, 900);
    setStyleSheet(UiTheme::appStyleSheet());

    // ── Context manager (heart of the app) ───────────────────────────────────
    ctx_mgr_ = new PacketContextManager(app_ctrl_, this);

    // ── Central splitter: LEFT = stream  |  RIGHT = analysis tabs ────────────
    main_splitter_ = new QSplitter(Qt::Horizontal, this);
    main_splitter_->setHandleWidth(3);
    setCentralWidget(main_splitter_);

    // ── LEFT — Live packet stream (30 % width) ────────────────────────────────
    stream_panel_ = new PacketStreamPanel(app_ctrl_, ctx_mgr_);
    stream_panel_->setMinimumWidth(280);
    main_splitter_->addWidget(stream_panel_);

    // ── RIGHT — Analysis tabs (70 % width) ────────────────────────────────────
    right_tabs_ = new QTabWidget();
    main_splitter_->addWidget(right_tabs_);

    main_splitter_->setStretchFactor(0, 3);   // stream ~30 %
    main_splitter_->setStretchFactor(1, 7);   // tabs   ~70 %

    // Instantiate all analysis views, each receives ctx_mgr_
    auto *overview_tab   = new NetworkOverviewTab(app_ctrl_, ctx_mgr_);
    auto *deep_dive_tab  = new PacketDeepDiveTab(app_ctrl_, ctx_mgr_);
    auto *encap_tab      = new TCPIPVisualizerTab(app_ctrl_, ctx_mgr_);
    auto *flow_tab       = new EndToEndFlowTab(app_ctrl_, ctx_mgr_);
    auto *diag_tab       = new DiagnosticsTab(app_ctrl_, ctx_mgr_);
    auto *buffer_tab     = new BuffersQueuesTab(app_ctrl_, ctx_mgr_);
    auto *nic_tab        = new NICPhysicalTab(app_ctrl_, ctx_mgr_);
    auto *heal_tab       = new AutoHealingTab(app_ctrl_, ctx_mgr_);

    right_tabs_->addTab(overview_tab,  "Overview");
    right_tabs_->addTab(deep_dive_tab, "Deep Dive");
    right_tabs_->addTab(encap_tab,     "Encapsulation");
    right_tabs_->addTab(flow_tab,      "Flow");
    right_tabs_->addTab(diag_tab,      "Diagnostics");
    right_tabs_->addTab(buffer_tab,    "Buffers");
    right_tabs_->addTab(nic_tab,       "NIC");
    right_tabs_->addTab(heal_tab,      "Auto-Healing");

    // ── Status bar ────────────────────────────────────────────────────────────
    status_mode_label_      = new QLabel("Mode: WAITING");
    status_interface_label_ = new QLabel("Interface: —");
    status_packets_label_   = new QLabel("Pkts: 0");
    status_flows_label_     = new QLabel("Flows: 0");
    statusBar()->addWidget(status_mode_label_);
    statusBar()->addWidget(new QLabel("  |  "));
    statusBar()->addWidget(status_interface_label_);
    statusBar()->addWidget(new QLabel("  |  "));
    statusBar()->addWidget(status_packets_label_);
    statusBar()->addWidget(new QLabel("  |  "));
    statusBar()->addWidget(status_flows_label_);

    // Active-packet status indicator
    auto *ctx_label = new QLabel("No packet selected");
    ctx_label->setStyleSheet(
        QString("color:%1; font-weight:600; padding:0 8px;").arg(UiTheme::kAccent));
    statusBar()->addPermanentWidget(ctx_label);
    connect(ctx_mgr_, &PacketContextManager::contextChanged,
            this, [ctx_label](PacketContext ctx) {
        if (!ctx.valid || !ctx.packet) {
            ctx_label->setText("No packet selected");
            return;
        }
        ctx_label->setText(
            QString("▶ #%1  %2  %3:%4→%5:%6")
                .arg(ctx.packet->id)
                .arg(QString::fromStdString(protocolToString(ctx.packet->protocol)))
                .arg(QString::fromStdString(ctx.packet->src_ip))
                .arg(ctx.packet->src_port)
                .arg(QString::fromStdString(ctx.packet->dst_ip))
                .arg(ctx.packet->dst_port));
    });

    // ── Toolbar ───────────────────────────────────────────────────────────────
    QToolBar *toolbar = addToolBar("Main");
    toolbar->setMovable(false);
    interface_combo_ = new QComboBox();
    for (const auto &iface : app_ctrl_->getNICModule().listInterfaces())
        interface_combo_->addItem(QString::fromStdString(iface));

    bpf_filter_edit_ = new QLineEdit();
    bpf_filter_edit_->setPlaceholderText("BPF capture filter");
    bpf_filter_edit_->setMinimumWidth(220);

    start_btn_ = new QPushButton("▶  Start");
    stop_btn_  = new QPushButton("■  Stop");

    toolbar->addWidget(new QLabel("  Interface: "));
    toolbar->addWidget(interface_combo_);
    toolbar->addWidget(new QLabel("  BPF: "));
    toolbar->addWidget(bpf_filter_edit_);
    toolbar->addSeparator();
    toolbar->addWidget(start_btn_);
    toolbar->addWidget(stop_btn_);

    connect(start_btn_, &QPushButton::clicked, this, [this] {
        const bool started = app_ctrl_->startCapture(
            interface_combo_->currentText(),
            bpf_filter_edit_->text());
        if (!started) {
            statusBar()->showMessage("Capture failed", 5000);
        }
    });
    connect(stop_btn_, &QPushButton::clicked, this, [this] {
        app_ctrl_->stopCapture();
    });

    // ── AppController signals ─────────────────────────────────────────────────
    connect(app_ctrl_, &AppController::captureStateChanged,
            this, &MainWindow::onCaptureStateChanged);
    connect(app_ctrl_, &AppController::metricsUpdated,
            this, &MainWindow::onMetricsUpdated);
    connect(app_ctrl_, &AppController::newEvent,
            this, &MainWindow::onNewEvent);
    connect(app_ctrl_, &AppController::captureError,
            this, [this](const QString &message) {
        statusBar()->showMessage(message, 8000);
        QMessageBox::critical(this, "Capture Error", message);
    });
}

void MainWindow::onCaptureStateChanged(QString mode)
{
    status_mode_label_->setText("Mode: " + mode);
    const char *color = (mode == "LIVE")      ? UiTheme::kGood
                       : (mode == "SIMULATED") ? UiTheme::kWarn
                                               : UiTheme::kMuted;
    status_mode_label_->setStyleSheet(
        QString("color:%1; font-weight:bold;").arg(color));
}

void MainWindow::onMetricsUpdated(NetworkMetrics metrics)
{
    status_packets_label_->setText("Pkts: " + QString::number(metrics.total_packets.load()));
    status_flows_label_->setText("Flows: " + QString::number(metrics.active_flows.load()));
}

void MainWindow::onNewEvent(Event evt)
{
    if (evt.type == EventType::INTERFACE_CHANGED) {
        try {
            status_interface_label_->setText(
                "Interface: " + QString::fromStdString(std::any_cast<std::string>(evt.payload)));
        } catch (...) {
            status_interface_label_->setText("Interface: updated");
        }
    }
    if (evt.type == EventType::CAPTURE_STARTED || evt.type == EventType::CAPTURE_STOPPED)
        statusBar()->showMessage(QString::fromStdString(evt.description), 3000);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    app_ctrl_->stopCapture();
    QMainWindow::closeEvent(event);
}
