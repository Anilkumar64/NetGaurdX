#include <memory>
#pragma once
#include <QWidget>
#include <QLabel>
#include <QTextEdit>
#include <QTabWidget>
#include <QTimer>
#include <QPushButton>
#include <QVector>
#include <cstddef>
#include "core/AppController.h"
#include "gui/PacketContextManager.h"

// ─────────────────────────────────────────────────────────────────────────────
//  TCPIPVisualizerTab
//
//  Shows packet encapsulation step-by-step:
//    Step 0  →  Application layer  (payload only)
//    Step 1  →  Transport layer    (TCP/UDP header slides in from left)
//    Step 2  →  Network layer      (IP header slides in from left)
//    Step 3  →  Link layer         (Ethernet header slides in from left)
//
//  Each header block slides in from the left side using a progress value
//  [0.0 … 1.0] that is driven either by the QTimer (Play) or set to 1.0
//  instantly (Step button).
// ─────────────────────────────────────────────────────────────────────────────

class TCPIPVisualizerTab : public QWidget
{
    Q_OBJECT
public:
    explicit TCPIPVisualizerTab(AppController *app_ctrl, PacketContextManager *ctx_mgr, QWidget *parent = nullptr);

public slots:
    void onLatestPacket(std::shared_ptr<const UnifiedPacket> pkt);
    void selectPacket(UnifiedPacket pkt);

private:
    // ── Inner canvas: draws the step-based packet diagram ──────────────────
    class StepCanvas;

    // ── UI construction ─────────────────────────────────────────────────────
    void buildUi();

    // ── Detail-tab population ────────────────────────────────────────────────
    void populateDetails();

    // ── Animation control ───────────────────────────────────────────────────
    void resetToStep0();
    void setPlaying(bool playing);
    void onTimerTick();
    void commitStep();
    void logStepStart(int step);
    void updateStageLabel();

    // ── Logging ──────────────────────────────────────────────────────────────
    void appendLog(const QString &layer, const QString &msg);

    // ── Payload description ──────────────────────────────────────────────────
    QString describePayload() const;
    QString formatHex(size_t offset, size_t len, size_t limit) const;

    // ── Step metadata ────────────────────────────────────────────────────────
    //  step_index_  ∈ {0,1,2,3}  — which layer we are currently animating IN
    //  step_progress_ ∈ [0,1]    — how far the current header has slid in
    //  After step_progress_ reaches 1.0 and the timer fires again, we advance
    //  step_index_ and restart progress at 0.
    int   step_index_{0};          // 0=App  1=Transport  2=Network  3=Link
    qreal step_progress_{1.0};     // 1.0 = fully visible (no slide in-progress)
    bool  playing_{false};
    bool  single_step_{false};
    static constexpr int kMaxStep = 3;
    static constexpr int kTickMs  = 20;   // timer interval
    static constexpr qreal kSpeedPerTick = 0.04; // progress added per tick

    // ── Packet state ─────────────────────────────────────────────────────────
    UnifiedPacket current_packet_;
    bool has_packet_{false};

    // ── Widgets ──────────────────────────────────────────────────────────────
    QLabel      *info_label_{nullptr};
    StepCanvas  *canvas_{nullptr};
    QPushButton *play_btn_{nullptr};
    QPushButton *pause_btn_{nullptr};
    QPushButton *step_btn_{nullptr};
    QPushButton *reset_btn_{nullptr};
    QLabel      *stage_label_{nullptr};
    QTextEdit   *log_view_{nullptr};
    QTabWidget  *outer_tabs_{nullptr};   // Encapsulation | Details
    QTabWidget  *detail_tabs_{nullptr};  // L2 | L3 | L4/L7 | Hex
    QTextEdit   *l2_view_{nullptr};
    QTextEdit   *l3_view_{nullptr};
    QTextEdit   *l4_view_{nullptr};
    QTextEdit   *hex_view_{nullptr};
    QTimer      *timer_{nullptr};

    // Step-name pill labels (Application → Transport → Network → Link)
    QVector<QLabel *> step_labels_;
};
