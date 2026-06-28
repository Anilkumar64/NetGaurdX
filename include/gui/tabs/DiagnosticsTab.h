#pragma once
#include <QWidget>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

class RootCausePanel;

class DiagnosticsTab : public QWidget {
    Q_OBJECT
public:
    explicit DiagnosticsTab(AppController        *app_ctrl,
                            PacketContextManager *ctx_mgr,
                            QWidget              *parent = nullptr);
public slots:
    void onNewEvent(Event evt);
    void onAlert(Event evt);
    void onDiagnosticsComplete(DiagnosticReport report);
    void onContextChanged(PacketContext ctx);
private:
    QTableWidget   *event_table_{nullptr};
    QPushButton    *run_diag_btn_{nullptr};
    QLabel         *health_summary_{nullptr};
    QLabel         *root_cause_header_{nullptr};
    RootCausePanel *root_cause_panel_{nullptr};
    AppController  *app_ctrl_{nullptr};
};
