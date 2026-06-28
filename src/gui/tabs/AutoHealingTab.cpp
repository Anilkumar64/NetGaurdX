#include "gui/tabs/AutoHealingTab.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QDateTime>
#include <QPainter>
#include <QPainterPath>
#include <QFontDatabase>
#include <QMouseEvent>
#include <QVariant>
#include <functional>
#include "core/Logger.h"
#include "gui/UiTheme.h"

// ═══════════════════════════════════════════════════════════════════════════
//  ActionCard  – shows a single healing suggestion with Execute button
//  NOTE: No Q_OBJECT macro — class is defined in a .cpp file so MOC won't
//        scan it. We use a plain std::function callback instead of signals.
// ═══════════════════════════════════════════════════════════════════════════
class ActionCard : public QWidget
{
public:
    struct Action
    {
        QString id;
        QString title;
        QString detail;
        QString impact; // "LOW" / "MED" / "HIGH"
        bool applied{false};
    };

    // Direct callback — assign a lambda after construction.
    // Called with the index of the action whose Execute button was clicked.
    std::function<void(int)> onExecute;

    explicit ActionCard(QWidget *parent = nullptr) : QWidget(parent)
    {
        setMinimumHeight(0);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    }

    void setActions(const std::vector<Action> &acts)
    {
        actions_ = acts;
        updateGeometry();
        update();
    }

    void markApplied(int idx)
    {
        if (idx >= 0 && idx < static_cast<int>(actions_.size()))
        {
            actions_[idx].applied = true;
            update();
        }
    }

    // Returns -1 if pos is not over any action row, otherwise the row index.
    int actionAt(const QPoint &pos) const
    {
        for (int i = 0; i < static_cast<int>(row_rects_.size()); ++i)
            if (row_rects_[i].contains(pos))
                return i;
        return -1;
    }

protected:
    QSize sizeHint() const override
    {
        return {400, static_cast<int>(actions_.size()) * 68 + 8};
    }

    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kBackground));

        row_rects_.clear();

        if (actions_.empty())
        {
            p.setPen(QColor(UiTheme::kMuted));
            QFont f = font();
            f.setItalic(true);
            p.setFont(f);
            p.drawText(rect().adjusted(16, 0, -16, 0), Qt::AlignVCenter,
                       "No healing actions — run diagnostics or select a packet with an issue");
            return;
        }

        int y = 4;
        for (int i = 0; i < static_cast<int>(actions_.size()); ++i)
        {
            const auto &a = actions_[i];
            QRectF card(4, y, rect().width() - 8, 62);
            row_rects_.push_back(card);

            // ── Card background ──────────────────────────────────────────
            p.setPen(QPen(QColor(a.applied ? UiTheme::kGood : UiTheme::kBorder), 1));
            p.setBrush(QColor(a.applied ? UiTheme::kGood : UiTheme::kPanel)
                           .darker(a.applied ? 130 : 100));
            p.drawRoundedRect(card, 8, 8);

            // ── Left accent stripe ────────────────────────────────────────
            QColor accent = (a.impact == "HIGH")  ? QColor(UiTheme::kBad)
                            : (a.impact == "MED") ? QColor(UiTheme::kWarn)
                                                  : QColor(UiTheme::kGood);
            p.setPen(Qt::NoPen);
            p.setBrush(accent);
            p.drawRoundedRect(QRectF(4, y + 6, 4, 50), 2, 2);

            // ── Impact badge ─────────────────────────────────────────────
            p.setBrush(accent.darker(140));
            p.drawRoundedRect(QRectF(16, y + 8, 36, 16), 4, 4);
            {
                QFont bf = font();
                bf.setPointSize(7);
                bf.setBold(true);
                p.setFont(bf);
                p.setPen(QColor("#06101f"));
                p.drawText(QRectF(16, y + 8, 36, 16), Qt::AlignCenter, a.impact);
            }

            // ── Action ID ────────────────────────────────────────────────
            {
                QFont idf = font();
                idf.setPointSize(7);
                p.setFont(idf);
                p.setPen(QColor(UiTheme::kMuted));
                p.drawText(QRectF(58, y + 8, 60, 16),
                           Qt::AlignLeft | Qt::AlignVCenter, a.id);
            }

            // ── Title ────────────────────────────────────────────────────
            {
                QFont tf = font();
                tf.setBold(true);
                tf.setPointSize(9);
                p.setFont(tf);
                p.setPen(a.applied ? QColor(UiTheme::kGood) : QColor(UiTheme::kText));
                p.drawText(QRectF(16, y + 26, card.width() - 110, 16),
                           Qt::AlignLeft | Qt::AlignVCenter,
                           a.applied ? "✓  " + a.title : a.title);
            }

            // ── Detail ───────────────────────────────────────────────────
            {
                QFont df = font();
                df.setPointSize(8);
                p.setFont(df);
                p.setPen(QColor(UiTheme::kMuted));
                p.drawText(QRectF(16, y + 44, card.width() - 110, 14),
                           Qt::AlignLeft | Qt::AlignVCenter, a.detail);
            }

            // ── Execute / Applied button ─────────────────────────────────
            if (!a.applied)
            {
                QRectF btn(card.right() - 90, y + 16, 82, 28);
                p.setPen(QPen(accent, 1));
                p.setBrush(accent.darker(160));
                p.drawRoundedRect(btn, 6, 6);

                QFont bnf = font();
                bnf.setPointSize(8);
                bnf.setBold(true);
                p.setFont(bnf);
                p.setPen(accent);
                p.drawText(btn, Qt::AlignCenter, "Execute");
            }
            else
            {
                QFont gf = font();
                gf.setPointSize(8);
                p.setFont(gf);
                p.setPen(QColor(UiTheme::kGood));
                p.drawText(QRectF(card.right() - 90, y + 16, 82, 28),
                           Qt::AlignCenter, "Applied ✓");
            }

            y += 68;
        }
    }

    void mousePressEvent(QMouseEvent *ev) override
    {
        const int idx = actionAt(ev->pos());
        if (idx < 0 || actions_[idx].applied)
            return;

        // Only fire if the click landed on the Execute button area.
        const QRectF &card = row_rects_[idx];
        QRectF btn(card.right() - 90, card.top() + 16, 82, 28);
        if (btn.contains(ev->pos()) && onExecute)
            onExecute(idx);
    }

private:
    std::vector<Action> actions_;
    mutable std::vector<QRectF> row_rects_;
};

// ═══════════════════════════════════════════════════════════════════════════
//  AutoHealingTab
// ═══════════════════════════════════════════════════════════════════════════

AutoHealingTab::AutoHealingTab(AppController *app_ctrl, PacketContextManager *ctx_mgr, QWidget *parent)
    : QWidget(parent), app_ctrl_(app_ctrl)
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(10, 10, 10, 10);
    root->setSpacing(8);

    // ── Status banner ──────────────────────────────────────────────────────
    selected_packet_label_ = new QLabel(
        "Auto-healing analyzes alerts and packet issues, then suggests corrective actions.\n"
        "Select a packet or run diagnostics to generate suggestions.");
    selected_packet_label_->setWordWrap(true);
    selected_packet_label_->setStyleSheet(
        QString("font-weight:700; color:%1; padding:10px;"
                "background:%2; border:1px solid %3; border-radius:8px;")
            .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
    root->addWidget(selected_packet_label_);

    // ── Action cards ───────────────────────────────────────────────────────
    auto *actLabel = new QLabel("Suggested healing actions");
    actLabel->setStyleSheet(
        QString("color:%1; font-weight:700; font-size:9pt;").arg(UiTheme::kMuted));
    root->addWidget(actLabel);

    action_card_ = new ActionCard(this);
    action_card_->setMinimumHeight(80);

    // Direct std::function callback — no Q_OBJECT / MOC needed.
    action_card_->onExecute = [this](int idx)
    {
        if (idx < 0 || idx >= static_cast<int>(pending_actions_.size()))
            return;

        app_ctrl_->executeHealing(pending_actions_[idx]);

        const QString ts = QDateTime::currentDateTime().toString("HH:mm:ss");
        history_log_->append(
            QString("[%1] Requested: %2")
                .arg(ts)
                .arg(QString::fromStdString(pending_actions_[idx].description)));
    };

    root->addWidget(action_card_);

    // ── History log ────────────────────────────────────────────────────────
    auto *histLabel = new QLabel("Execution history & system messages");
    histLabel->setStyleSheet(
        QString("color:%1; font-weight:700; font-size:9pt;").arg(UiTheme::kMuted));
    root->addWidget(histLabel);

    history_log_ = new QTextEdit(this);
    history_log_->setReadOnly(true);
    history_log_->setMaximumHeight(160);
    history_log_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    history_log_->setStyleSheet(
        QString("background:%1; color:%2; border:1px solid %3; padding:6px;")
            .arg(UiTheme::kPanel, UiTheme::kText, UiTheme::kBorder));
    history_log_->setText("[System ready — waiting for alerts or packet selection]");
    root->addWidget(history_log_);
    root->addStretch(1);

    // ── AppController signal connections ───────────────────────────────────
    connect(app_ctrl, &AppController::healingActionsSuggested,
            this, &AutoHealingTab::onHealingActionsSuggested);
    connect(app_ctrl, &AppController::diagnosticsComplete,
            this, &AutoHealingTab::onDiagnosticsComplete);
    connect(app_ctrl, &AppController::alertTriggered,
            this, &AutoHealingTab::onHealingAction);
    connect(app_ctrl, &AppController::selectedPacketChanged,
            this, &AutoHealingTab::onSelectedPacket);
    connect(ctx_mgr, &PacketContextManager::contextChanged,
            this, &AutoHealingTab::onContextChanged);
}

// ── Slot implementations ────────────────────────────────────────────────────

void AutoHealingTab::onHealingActionsSuggested(std::vector<HealingAction> actions)
{
    pending_actions_ = std::move(actions);

    std::vector<ActionCard::Action> cards;
    cards.reserve(pending_actions_.size());
    for (const auto &a : pending_actions_)
    {
        ActionCard::Action c;
        c.id = QString::fromStdString(a.id);
        c.title = QString::fromStdString(a.description);
        c.detail = QString::fromStdString(a.command);
        c.impact = "MED";
        cards.push_back(std::move(c));
    }
    action_card_->setActions(cards);
}

void AutoHealingTab::onContextChanged(PacketContext ctx)
{
    if (ctx.valid && ctx.packet) {
        setProperty("activePacketId", QVariant::fromValue<qulonglong>(ctx.packet->id));
        onSelectedPacket(ctx.packet);
        return;
    }

    setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
    selected_packet_label_->setText(
        "Auto-healing analyzes alerts and packet issues, then suggests corrective actions.\n"
        "Select a packet or run diagnostics to generate suggestions.");
    selected_packet_label_->setStyleSheet(
        QString("font-weight:700; color:%1; padding:10px;"
                "background:%2; border:1px solid %3; border-radius:8px;")
            .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
    last_proto_ = Protocol::UNKNOWN;
    last_flags_ = 0xFF;
    pending_actions_.clear();
    action_card_->setActions({});
}

void AutoHealingTab::onDiagnosticsComplete(DiagnosticReport report)
{
    const QString ts = QDateTime::currentDateTime().toString("HH:mm:ss");
    history_log_->append(
        QString("[%1] Diagnostics: %2")
            .arg(ts)
            .arg(QString::fromStdString(report.summary)));
}

void AutoHealingTab::onHealingAction(Event evt)
{
    if (evt.type != EventType::HEALING_ACTION)
        return;

    const QString ts = QDateTime::currentDateTime().toString("HH:mm:ss");
    try
    {
        const auto result = std::any_cast<HealingResult>(evt.payload);
        if (result.success)
        {
            for (int i = 0; i < static_cast<int>(pending_actions_.size()); ++i)
            {
                if (pending_actions_[i].id == result.action.id)
                {
                    action_card_->markApplied(i);
                    break;
                }
            }
        }
        history_log_->append(
            QString("[%1] %2: %3 | command: %4 | executed: %5 | exit code: %6")
                .arg(ts)
                .arg(result.success ? "Success" : "Failed")
                .arg(QString::fromStdString(result.action.description))
                .arg(QString::fromStdString(result.action.command))
                .arg(result.executed ? "yes" : "no")
                .arg(result.exit_code));
        return;
    }
    catch (const std::bad_any_cast&)
    {
    }

    history_log_->append(
        QString("[%1] System: %2")
            .arg(ts)
            .arg(QString::fromStdString(evt.description)));
}

void AutoHealingTab::onSelectedPacket(std::shared_ptr<const UnifiedPacket> pkt)
{
    if (!pkt) return;
    // Dereference once at slot boundary for the rest of this function
    const UnifiedPacket &p = *pkt;
    const Protocol proto = p.protocol;
    const uint8_t flags = p.tcp_flags;
    if (proto == last_proto_ && flags == last_flags_)
        return;
    last_proto_ = proto;
    last_flags_ = flags;

    // ── Update status banner ───────────────────────────────────────────────
    selected_packet_label_->setText(
        QString("▶  Packet #%1  |  %2  |  flow %3  |  %4 B")
            .arg(p.id)
            .arg(QString::fromStdString(protocolToString(p.protocol)))
            .arg(p.flow_id)
            .arg(p.packet_size));
    selected_packet_label_->setStyleSheet(
        QString("font-weight:700; color:%1; padding:10px;"
                "background:%2; border:1px solid %3; border-radius:8px;")
            .arg(UiTheme::kAccent, UiTheme::kPanel, UiTheme::kBorder));

    // ── Build contextual healing cards ────────────────────────────────────
    std::vector<ActionCard::Action> cards;

    // TCP RST — connection reset by peer or firewall
    if (p.has_tcp && (p.tcp_flags & 0x04))
    {
        cards.push_back({"RST-01",
                         "Inspect firewall rules for this flow",
                         QString("Check iptables/nftables rules for dst %1:%2")
                             .arg(QString::fromStdString(p.dst_ip))
                             .arg(p.dst_port),
                         "HIGH"});
        cards.push_back({"RST-02",
                         "Verify destination port is listening",
                         QString("ss -tlnp | grep :%1").arg(p.dst_port),
                         "HIGH"});
    }

    // TCP SYN with no payload — potential connection-initiation issue
    if (p.has_tcp && (p.tcp_flags & 0x02) && p.payload_len == 0)
    {
        cards.push_back({"SYN-01",
                         "Enable TCP SYN retry with backoff",
                         "net.ipv4.tcp_syn_retries = 6 (sysctl)",
                         "MED"});
    }

    // DNS with no answers — resolver failure
    if (p.has_dns && p.dns_info.answers.empty())
    {
        cards.push_back({"DNS-01",
                         "Switch to alternate DNS resolver",
                         "Try 8.8.8.8 or 1.1.1.1 — check /etc/resolv.conf",
                         "MED"});
        cards.push_back({"DNS-02",
                         "Flush DNS cache",
                         "systemd-resolve --flush-caches",
                         "LOW"});
    }

    // Very low TTL — routing loop suspected
    if (p.ip_hdr.ttl > 0 && p.ip_hdr.ttl < 5)
    {
        cards.push_back({"TTL-01",
                         "Investigate routing loop",
                         "traceroute " + QString::fromStdString(p.dst_ip),
                         "HIGH"});
    }

    // Oversized payload — possible MTU mismatch
    if (p.payload_len > 1400)
    {
        cards.push_back({"MTU-01",
                         "Enable Path MTU discovery",
                         "ip route change default mtu 1500 advmss 1460",
                         "LOW"});
    }

    // Fallback — packet looks fine
    if (cards.empty())
    {
        cards.push_back({"OK-01",
                         "No issues detected for this packet type",
                         QString::fromStdString(protocolToString(p.protocol)) + " packet looks healthy",
                         "LOW"});
    }

    // ── Sync pending_actions_ with the displayed cards ────────────────────
    pending_actions_.clear();
    pending_actions_.reserve(cards.size());
    for (const auto &c : cards)
    {
        HealingAction ha;
        ha.id = c.id.toStdString();
        ha.description = c.title.toStdString();
        ha.command = c.detail.toStdString();
        pending_actions_.push_back(std::move(ha));
    }

    action_card_->setActions(cards);
}
