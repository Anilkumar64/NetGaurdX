#include "gui/tabs/NetworkOverviewTab.h"
#include <QGridLayout>
#include <QPainter>
#include <QPainterPath>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QDateTime>
#include <QFontDatabase>
#include <QVariant>
#include <deque>
#include <algorithm>
#include <cmath>
#include "core/Logger.h"
#include "gui/UiTheme.h"

// ── Sparkline widget ────────────────────────────────────────────────────────

class SparklineWidget : public QWidget
{
public:
    explicit SparklineWidget(const QString& title, const QColor& lineColor, QWidget* parent = nullptr)
        : QWidget(parent), title_(title), line_color_(lineColor)
    {
        setMinimumHeight(90);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void pushValue(double v)
    {
        values_.push_back(v);
        if ((int)values_.size() > kMaxPoints)
            values_.pop_front();
        current_value_ = v;
        update();
    }

    void setUnit(const QString& u) { unit_ = u; }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kPanel));
        p.setPen(QPen(QColor(UiTheme::kBorder), 1));
        p.drawRoundedRect(rect().adjusted(0,0,-1,-1), 8, 8);

        QRectF inner = QRectF(rect()).adjusted(12, 10, -12, -10);

        QFont bold = font(); bold.setBold(true); bold.setPointSize(9);
        p.setFont(bold);
        p.setPen(QColor(UiTheme::kMuted));
        p.drawText(inner.left(), inner.top(), inner.width(), 18, Qt::AlignLeft | Qt::AlignVCenter, title_);

        QFont valFont = font(); valFont.setBold(true); valFont.setPointSize(14);
        p.setFont(valFont);
        p.setPen(line_color_);
        p.drawText(inner.left(), inner.top() + 18, inner.width(), 24, Qt::AlignLeft | Qt::AlignVCenter,
                   formatValue(current_value_) + " " + unit_);

        if ((int)values_.size() < 2) return;

        QRectF graphRect = inner.adjusted(0, 46, 0, 0);
        double maxVal = *std::max_element(values_.begin(), values_.end());
        if (maxVal <= 0) maxVal = 1;

        QLinearGradient grad(graphRect.topLeft(), graphRect.bottomLeft());
        QColor fill = line_color_; fill.setAlphaF(0.18);
        grad.setColorAt(0, fill);
        fill.setAlphaF(0.0);
        grad.setColorAt(1, fill);

        QPainterPath fillPath, linePath;
        bool first = true;
        for (int i = 0; i < (int)values_.size(); ++i)
        {
            double x = graphRect.left() + (double)i / (kMaxPoints - 1) * graphRect.width();
            double y = graphRect.bottom() - (values_[i] / maxVal) * graphRect.height();
            if (first) { fillPath.moveTo(x, graphRect.bottom()); fillPath.lineTo(x, y); linePath.moveTo(x, y); first = false; }
            else { fillPath.lineTo(x, y); linePath.lineTo(x, y); }
        }
        fillPath.lineTo(graphRect.right(), graphRect.bottom());
        fillPath.closeSubpath();

        p.setPen(Qt::NoPen); p.setBrush(grad); p.drawPath(fillPath);
        p.setPen(QPen(line_color_, 2, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
        p.setBrush(Qt::NoBrush); p.drawPath(linePath);

        if (!values_.empty()) {
            double x = graphRect.right();
            double y = graphRect.bottom() - (values_.back() / maxVal) * graphRect.height();
            p.setPen(Qt::NoPen); p.setBrush(line_color_);
            p.drawEllipse(QPointF(x, y), 4, 4);
        }
    }

private:
    static QString formatValue(double v)
    {
        if (v >= 1e9) return QString::number(v/1e9,'f',1) + "G";
        if (v >= 1e6) return QString::number(v/1e6,'f',1) + "M";
        if (v >= 1e3) return QString::number(v/1e3,'f',1) + "K";
        return QString::number((int)v);
    }
    static constexpr int kMaxPoints = 60;
    QString title_, unit_;
    QColor line_color_;
    std::deque<double> values_;
    double current_value_{0};
};

// ── Protocol breakdown bar ──────────────────────────────────────────────────

class ProtocolBar : public QWidget
{
public:
    explicit ProtocolBar(QWidget* parent = nullptr) : QWidget(parent)
    { setMinimumHeight(52); setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed); }

    void setProtocols(const std::vector<std::tuple<QString,int,QColor>>& protos)
    { protocols_ = protos; update(); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kPanel));
        p.setPen(QPen(QColor(UiTheme::kBorder), 1));
        p.drawRoundedRect(rect().adjusted(0,0,-1,-1), 8, 8);

        int total = 0;
        for (auto& [n,c,col] : protocols_) total += c;

        if (protocols_.empty() || total == 0) {
            p.setPen(QColor(UiTheme::kMuted));
            QFont f = font(); f.setPointSize(8); p.setFont(f);
            p.drawText(rect().adjusted(12,0,-12,0), Qt::AlignVCenter, "Waiting for traffic...");
            return;
        }

        QRectF bar(12, 8, width()-24, 16);
        double x = bar.left();
        for (auto& [name, count, color] : protocols_) {
            double w = bar.width() * count / (double)total;
            p.setPen(Qt::NoPen); p.setBrush(color);
            p.drawRoundedRect(QRectF(x, bar.top(), std::max(w,2.0), bar.height()), 4, 4);
            x += w;
        }

        QFont f = font(); f.setPointSize(8); p.setFont(f);
        double lx = 12;
        for (auto& [name, count, color] : protocols_) {
            p.setPen(Qt::NoPen); p.setBrush(color);
            p.drawRoundedRect(QRectF(lx, 30, 10, 10), 2, 2);
            p.setPen(QColor(UiTheme::kMuted));
            QString label = name + " " + QString::number(100*count/total) + "%";
            p.drawText(QRectF(lx+14, 28, 90, 14), Qt::AlignLeft|Qt::AlignVCenter, label);
            lx += 96;
            if (lx > width()-60) break;
        }
    }

private:
    std::vector<std::tuple<QString,int,QColor>> protocols_;
};

// ── Alert ticker ────────────────────────────────────────────────────────────

class AlertTicker : public QWidget
{
public:
    explicit AlertTicker(QWidget* parent = nullptr) : QWidget(parent)
    { setMinimumHeight(34); setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed); }

    void addAlert(const QString& text, bool critical)
    {
        alerts_.push_front({text, critical, QDateTime::currentDateTime().toString("HH:mm:ss")});
        if ((int)alerts_.size() > 8) alerts_.pop_back();
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kPanel));
        p.setPen(QPen(QColor(UiTheme::kBorder), 1));
        p.drawRoundedRect(rect().adjusted(0,0,-1,-1), 6, 6);

        QFont f = font(); f.setPointSize(8); p.setFont(f);
        if (alerts_.empty()) {
            p.setPen(QColor(UiTheme::kMuted));
            p.drawText(rect().adjusted(12,0,-12,0), Qt::AlignVCenter, "No alerts — network healthy");
            return;
        }
        double x = 12;
        QFontMetrics fm(font());
        for (auto& a : alerts_) {
            QString label = "[" + a.time + "] " + (a.critical ? "⚠ " : "● ") + a.text + "   ";
            p.setPen(a.critical ? QColor(UiTheme::kBad) : QColor(UiTheme::kWarn));
            double w = fm.horizontalAdvance(label);
            p.drawText(QRectF(x, 0, w, height()), Qt::AlignVCenter, label);
            x += w + 16;
            if (x > width()) break;
        }
    }

private:
    struct Alert { QString text; bool critical; QString time; };
    std::deque<Alert> alerts_;
};

// ── Packet context card ─────────────────────────────────────────────────────

class PacketContextCard : public QWidget
{
public:
    explicit PacketContextCard(QWidget* parent = nullptr) : QWidget(parent)
    { setMinimumHeight(80); setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed); }

    void setPacket(const UnifiedPacket& pkt) { has_packet_ = true; pkt_ = pkt; update(); }
    void clear() { has_packet_ = false; pkt_ = UnifiedPacket{}; update(); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kPanelAlt));
        p.setPen(QPen(QColor(UiTheme::kAccent), 1));
        p.drawRoundedRect(rect().adjusted(0,0,-1,-1), 8, 8);

        QRectF inner = QRectF(rect()).adjusted(16, 10, -16, -10);

        if (!has_packet_) {
            p.setPen(QColor(UiTheme::kMuted));
            QFont f = font(); f.setItalic(true); p.setFont(f);
            p.drawText(inner, Qt::AlignVCenter, "No packet selected — click any row in Packet Stream to activate context across all tabs");
            return;
        }

        p.setPen(Qt::NoPen); p.setBrush(QColor(UiTheme::kAccent));
        p.drawRoundedRect(QRectF(0, 8, 4, height()-16), 2, 2);

        QFont bold = font(); bold.setBold(true); bold.setPointSize(10);
        p.setFont(bold); p.setPen(QColor(UiTheme::kAccent));
        p.drawText(inner.left(), inner.top(), inner.width(), 20, Qt::AlignLeft|Qt::AlignVCenter,
                   QString("▶  Active Packet #%1  —  context active across all tabs").arg(pkt_.id));

        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mono.setPointSize(9);
        p.setFont(mono); p.setPen(QColor(UiTheme::kText));
        QString flags;
        if (pkt_.has_tcp) flags = "  [" + QString::fromStdString(tcpFlagsToString(pkt_.tcp_flags)) + "]";
        p.drawText(inner.left(), inner.top()+22, inner.width(), 18, Qt::AlignLeft|Qt::AlignVCenter,
                   QString("%1:%2  →  %3:%4   %5%6")
                       .arg(QString::fromStdString(pkt_.src_ip)).arg(pkt_.src_port)
                       .arg(QString::fromStdString(pkt_.dst_ip)).arg(pkt_.dst_port)
                       .arg(QString::fromStdString(protocolToString(pkt_.protocol))).arg(flags));

        p.setPen(QColor(UiTheme::kMuted));
        QFont sm = font(); sm.setPointSize(8); p.setFont(sm);
        p.drawText(inner.left(), inner.top()+42, inner.width(), 16, Qt::AlignLeft|Qt::AlignVCenter,
                   QString("Flow %1  |  %2 bytes  |  TTL %3  |  Seq %4  |  Ack %5")
                       .arg(pkt_.flow_id).arg(pkt_.packet_size).arg(pkt_.ip_hdr.ttl)
                       .arg(pkt_.seq_num).arg(pkt_.ack_num));
    }

private:
    bool has_packet_{false};
    UnifiedPacket pkt_;
};

// ── NetworkOverviewTab ──────────────────────────────────────────────────────

NetworkOverviewTab::NetworkOverviewTab(AppController* app_ctrl, PacketContextManager *ctx_mgr, QWidget* parent)
    : QWidget(parent), app_ctrl_(app_ctrl)
{
    QVBoxLayout* layout = new QVBoxLayout(this);
    layout->setContentsMargins(14, 14, 14, 14);
    layout->setSpacing(10);

    // Stat pills
    QHBoxLayout* pills = new QHBoxLayout();
    pills->setSpacing(10);
    auto makePill = [](const QString& text, QLabel*& lbl) -> QLabel* {
        lbl = new QLabel(text);
        lbl->setMinimumHeight(38);
        lbl->setAlignment(Qt::AlignCenter);
        lbl->setStyleSheet(QString("font-weight:800; font-size:11pt; color:%1; padding:8px 14px;"
                                   "background:%2; border:1px solid %3; border-radius:8px;")
                               .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
        return lbl;
    };
    pills->addWidget(makePill("PPS: 0", pps_label_));
    pills->addWidget(makePill("BPS: 0", bps_label_));
    pills->addWidget(makePill("Flows: 0", flows_label_));
    pills->addWidget(makePill("Pkts: 0", packets_label_));
    pills->addWidget(makePill("Health: WAITING", health_label_));
    layout->addLayout(pills);

    // Packet context
    packet_card_ = new PacketContextCard();
    layout->addWidget(packet_card_);

    // Sparklines
    QHBoxLayout* sparks = new QHBoxLayout(); sparks->setSpacing(10);
    pps_spark_ = new SparklineWidget("Packets / second", QColor(UiTheme::kAccent)); pps_spark_->setUnit("pps");
    bps_spark_ = new SparklineWidget("Bytes / second",   QColor(UiTheme::kPayload)); bps_spark_->setUnit("bps");
    sparks->addWidget(pps_spark_); sparks->addWidget(bps_spark_);
    layout->addLayout(sparks);

    // Protocol bar
    QLabel* protoTitle = new QLabel("Protocol mix (rolling)");
    protoTitle->setStyleSheet(QString("color:%1; font-weight:700; font-size:9pt;").arg(UiTheme::kMuted));
    layout->addWidget(protoTitle);
    proto_bar_ = new ProtocolBar();
    layout->addWidget(proto_bar_);

    // Alert ticker
    QLabel* alertTitle = new QLabel("Recent alerts");
    alertTitle->setStyleSheet(QString("color:%1; font-weight:700; font-size:9pt;").arg(UiTheme::kMuted));
    layout->addWidget(alertTitle);
    alert_ticker_ = new AlertTicker();
    layout->addWidget(alert_ticker_);

    layout->addStretch(1);

    connect(app_ctrl_, &AppController::metricsUpdated,       this, &NetworkOverviewTab::onMetricsUpdated);
    connect(app_ctrl_, &AppController::healthChanged,        this, &NetworkOverviewTab::onHealthChanged);
    connect(app_ctrl_, &AppController::alertTriggered,       this, &NetworkOverviewTab::onAlert);
    connect(app_ctrl_, &AppController::selectedPacketChanged,this, &NetworkOverviewTab::onSelectedPacket);
    connect(app_ctrl_, &AppController::packetReceived,       this, &NetworkOverviewTab::onPacketReceived);
    connect(ctx_mgr, &PacketContextManager::contextChanged,  this, &NetworkOverviewTab::onContextChanged);
}

void NetworkOverviewTab::onPacketReceived(std::shared_ptr<const UnifiedPacket> pkt)
{
    if (!pkt) return;
    proto_counts_[pkt->protocol]++;
    total_proto_count_++;
    if (total_proto_count_ % 50 == 0)
    {
        static const struct { Protocol p; const char* n; const char* c; } kProtos[] = {
            {Protocol::TCP,   "TCP",   UiTheme::kTcp},
            {Protocol::UDP,   "UDP",   UiTheme::kIp},
            {Protocol::HTTP,  "HTTP",  UiTheme::kPayload},
            {Protocol::DNS,   "DNS",   UiTheme::kWarn},
            {Protocol::HTTPS, "HTTPS", UiTheme::kGood},
            {Protocol::QUIC,  "QUIC",  UiTheme::kGood},
            {Protocol::ICMP,  "ICMP",  UiTheme::kMuted},
        };
        std::vector<std::tuple<QString,int,QColor>> protos;
        for (auto& kp : kProtos) {
            auto it = proto_counts_.find(kp.p);
            if (it != proto_counts_.end() && it->second > 0)
                protos.emplace_back(kp.n, it->second, QColor(kp.c));
        }
        proto_bar_->setProtocols(protos);
    }
}

void NetworkOverviewTab::onMetricsUpdated(NetworkMetrics metrics)
{
    Logger::instance().log(LogLevel::DEBUG, "GUI", "NetworkOverviewTab slot called, updating widget");
    uint64_t pps = metrics.packets_per_second.load();
    uint64_t bps = metrics.bytes_per_second.load();
    pps_label_->setText("PPS: " + QString::number(pps));
    bps_label_->setText("BPS: " + QString::number(bps));
    flows_label_->setText("Flows: " + QString::number(metrics.active_flows.load()));
    packets_label_->setText("Pkts: " + QString::number(metrics.total_packets.load()));
    pps_spark_->pushValue((double)pps);
    bps_spark_->pushValue((double)bps);
}

void NetworkOverviewTab::onHealthChanged(SystemHealth health)
{
    Logger::instance().log(LogLevel::DEBUG, "GUI", "NetworkOverviewTab slot called, updating widget");
    health_label_->setText("Health: " + QString::fromStdString(health.status_message));
    const char* color = health.overall == HealthStatus::HEALTHY  ? UiTheme::kGood
                       : health.overall == HealthStatus::DEGRADED ? UiTheme::kWarn
                                                                   : UiTheme::kBad;
    health_label_->setStyleSheet(
        QString("font-weight:800;font-size:11pt;color:%1;padding:8px 14px;background:%2;border:1px solid %1;border-radius:8px;")
            .arg(color, UiTheme::kPanel));
}

void NetworkOverviewTab::onAlert(Event evt)
{
    Logger::instance().log(LogLevel::DEBUG, "GUI", "NetworkOverviewTab slot called, updating widget");
    bool critical = (evt.type == EventType::ALERT_TCP_RESET || evt.type == EventType::ALERT_PACKET_LOSS);
    alert_ticker_->addAlert(QString::fromStdString(evt.description), critical);
    health_label_->setStyleSheet(
        QString("font-weight:800;font-size:11pt;color:%1;padding:8px 14px;background:%2;border:1px solid %1;border-radius:8px;")
            .arg(UiTheme::kBad, UiTheme::kPanel));
    if      (evt.type == EventType::ALERT_DNS_FAILURE)         health_label_->setText("Health: DNS ALERT");
    else if (evt.type == EventType::ALERT_PACKET_LOSS)         health_label_->setText("Health: PACKET LOSS");
    else if (evt.type == EventType::ALERT_HIGH_RETRANSMISSION) health_label_->setText("Health: HIGH RETX");
    else if (evt.type == EventType::ALERT_TCP_RESET)           health_label_->setText("Health: TCP RESET");
    else health_label_->setText("Health: " + QString::fromStdString(evt.description));
}

void NetworkOverviewTab::onSelectedPacket(std::shared_ptr<const UnifiedPacket> pkt)
{
    if (pkt) packet_card_->setPacket(*pkt);
}

void NetworkOverviewTab::onContextChanged(PacketContext ctx)
{
    if (ctx.valid && ctx.packet) {
        setProperty("activePacketId", QVariant::fromValue<qulonglong>(ctx.packet->id));
        onSelectedPacket(ctx.packet);
        return;
    }
    setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
    packet_card_->clear();
}
