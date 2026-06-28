#include "gui/tabs/NICPhysicalTab.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPainter>
#include <QPainterPath>
#include <QTimer>
#include <QFontDatabase>
#include <QVariant>
#include <deque>
#include <algorithm>
#include "core/Logger.h"
#include "gui/UiTheme.h"

// ── NIC stats card ────────────────────────────────────────────────────────
class NicStatsCard : public QWidget
{
public:
    explicit NicStatsCard(QWidget *parent = nullptr) : QWidget(parent)
    {
        setMinimumHeight(220);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void update(const NICInfo &stats)
    {
        stats_ = stats;
        rx_hist_.push_back(stats.stats.rx_bytes);
        tx_hist_.push_back(stats.stats.tx_bytes);
        if ((int)rx_hist_.size() > kMax)
            rx_hist_.pop_front();
        if ((int)tx_hist_.size() > kMax)
            tx_hist_.pop_front();
        QWidget::update();
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kPanel));
        p.setPen(QPen(QColor(UiTheme::kBorder), 1));
        p.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 8, 8);

        QRectF inner = QRectF(rect()).adjusted(16, 12, -16, -12);

        // Header
        QFont hf = font();
        hf.setBold(true);
        hf.setPointSize(11);
        p.setFont(hf);
        p.setPen(QColor(UiTheme::kEthernet));
        p.drawText(inner.left(), inner.top(), inner.width(), 24,
                   Qt::AlignLeft | Qt::AlignVCenter,
                   "NIC: " + QString::fromStdString(stats_.mac_address.empty() ? "eth0" : stats_.ipv4_address));

        // Fields grid
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mono.setPointSize(9);
        p.setFont(mono);

        struct Row
        {
            QString key;
            QString val;
        };
        std::vector<Row> rows = {
            {"MAC address", QString::fromStdString(stats_.mac_address)},
            {"IPv4 address", QString::fromStdString(stats_.ipv4_address)},
            {"RX bytes", QString::number(stats_.stats.rx_bytes)},
            {"TX bytes", QString::number(stats_.stats.tx_bytes)},
            {"RX packets", QString::number(stats_.stats.rx_packets)},
            {"TX packets", QString::number(stats_.stats.tx_packets)},
            {"RX drops", QString::number(stats_.stats.rx_dropped)},
            {"TX drops", QString::number(stats_.stats.tx_dropped)},
            {"RX errors", QString::number(stats_.stats.rx_errors)},
            {"TX errors", QString::number(stats_.stats.tx_errors)},
        };

        double y = inner.top() + 28;
        QFontMetrics fm(mono);
        int keyW = fm.horizontalAdvance("IPv4 address  ");
        for (auto &r : rows)
        {
            p.setPen(QColor(UiTheme::kMuted));
            p.drawText(QRectF(inner.left(), y, keyW, 16),
                       Qt::AlignLeft | Qt::AlignVCenter, r.key + ":");
            p.setPen(QColor(UiTheme::kText));
            p.drawText(QRectF(inner.left() + keyW, y, inner.width() - keyW, 16),
                       Qt::AlignLeft | Qt::AlignVCenter, r.val);
            y += 17;
            if (y + 17 > inner.bottom())
                break;
        }

        // Mini sparkline for RX bytes delta
        if ((int)rx_hist_.size() >= 2)
        {
            QRectF spark(inner.right() - 130, inner.top() + 28, 120, 50);
            p.setPen(Qt::NoPen);
            p.setBrush(QColor(UiTheme::kPanelAlt));
            p.drawRoundedRect(spark, 4, 4);

            std::vector<double> deltas;
            for (int i = 1; i < (int)rx_hist_.size(); ++i)
                deltas.push_back(std::max(0.0, (double)(rx_hist_[i] - rx_hist_[i - 1])));
            double maxD = *std::max_element(deltas.begin(), deltas.end());
            if (maxD <= 0)
                maxD = 1;

            QPainterPath sparkPath;
            bool first = true;
            for (int i = 0; i < (int)deltas.size(); ++i)
            {
                double x = spark.left() + 2 + (double)i / (kMax - 1) * (spark.width() - 4);
                double y2 = spark.bottom() - 2 - deltas[i] / maxD * (spark.height() - 4);
                if (first)
                {
                    sparkPath.moveTo(x, y2);
                    first = false;
                }
                else
                    sparkPath.lineTo(x, y2);
            }
            p.setPen(QPen(QColor(UiTheme::kEthernet), 1.5));
            p.setBrush(Qt::NoBrush);
            p.drawPath(sparkPath);

            QFont sf = font();
            sf.setPointSize(7);
            p.setFont(sf);
            p.setPen(QColor(UiTheme::kMuted));
            p.drawText(spark.adjusted(2, 0, -2, -2).toRect(), Qt::AlignBottom | Qt::AlignLeft, "RX Δbytes");
        }
    }

private:
    static constexpr int kMax = 30;
    NICInfo stats_;
    std::deque<uint64_t> rx_hist_, tx_hist_;
};

// ── Frame decode card ─────────────────────────────────────────────────────
class FrameDecodeCard : public QWidget
{
public:
    explicit FrameDecodeCard(QWidget *parent = nullptr) : QWidget(parent)
    {
        setMinimumHeight(130);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void setPacket(const UnifiedPacket &pkt)
    {
        pkt_ = pkt;
        has_ = true;
        QWidget::update();
    }

    void clearPacket()
    {
        pkt_ = UnifiedPacket{};
        has_ = false;
        QWidget::update();
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kPanel));
        p.setPen(QPen(QColor(UiTheme::kBorder), 1));
        p.drawRoundedRect(rect().adjusted(0, 0, -1, -1), 8, 8);

        QRectF inner = QRectF(rect()).adjusted(16, 12, -16, -12);

        QFont hf = font();
        hf.setBold(true);
        hf.setPointSize(9);
        p.setFont(hf);
        p.setPen(QColor(UiTheme::kText));
        p.drawText(inner.left(), inner.top(), inner.width(), 20,
                   Qt::AlignLeft | Qt::AlignVCenter, "Selected frame at NIC layer");

        if (!has_)
        {
            p.setPen(QColor(UiTheme::kMuted));
            QFont f = font();
            f.setItalic(true);
            p.setFont(f);
            p.drawText(inner.adjusted(0, 24, 0, 0), Qt::AlignTop,
                       "Select a packet in the stream to see its Ethernet frame decode");
            return;
        }

        auto macStr = [](const uint8_t mac[6]) -> QString
        {
            return QString("%1:%2:%3:%4:%5:%6")
                .arg(mac[0], 2, 16, QChar('0'))
                .arg(mac[1], 2, 16, QChar('0'))
                .arg(mac[2], 2, 16, QChar('0'))
                .arg(mac[3], 2, 16, QChar('0'))
                .arg(mac[4], 2, 16, QChar('0'))
                .arg(mac[5], 2, 16, QChar('0'));
        };

        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mono.setPointSize(8);
        p.setFont(mono);
        QFontMetrics fm(mono);
        int kw = fm.horizontalAdvance("Ethertype    ");

        struct R
        {
            QString k, v;
        };
        std::vector<R> rows = {
            {"Frame #", QString::number(pkt_.id)},
            {"Total", QString("%1 B  (eth %2 + ip %3 + transport %4 + payload %5)")
                          .arg(pkt_.packet_size)
                          .arg(pkt_.eth_len)
                          .arg(pkt_.ip_len)
                          .arg(pkt_.transport_len)
                          .arg(pkt_.payload_len)},
            {"Src MAC", macStr(pkt_.eth_hdr.src)},
            {"Dst MAC", macStr(pkt_.eth_hdr.dst)},
            {"Ethertype", QString("0x%1").arg(pkt_.eth_hdr.ethertype, 4, 16, QChar('0'))},
            {"Direction", pkt_.direction == Direction::RX ? "RX (incoming)" : pkt_.direction == Direction::TX ? "TX (outgoing)"
                                                                                                              : "Unknown"},
            {"Protocol", QString::fromStdString(protocolToString(pkt_.protocol))},
        };

        double y = inner.top() + 24;
        for (auto &r : rows)
        {
            p.setPen(QColor(UiTheme::kMuted));
            p.drawText(QRectF(inner.left(), y, kw, 15), Qt::AlignLeft | Qt::AlignVCenter, r.k + ":");
            p.setPen(QColor(UiTheme::kText));
            p.drawText(QRectF(inner.left() + kw, y, inner.width() - kw, 15),
                       Qt::AlignLeft | Qt::AlignVCenter, r.v);
            y += 15;
            if (y + 15 > inner.bottom())
                break;
        }
    }

private:
    UnifiedPacket pkt_;
    bool has_{false};
};

// ── NICPhysicalTab ────────────────────────────────────────────────────────
NICPhysicalTab::NICPhysicalTab(AppController *app_ctrl, PacketContextManager *ctx_mgr, QWidget *parent)
    : QWidget(parent)
    , app_ctrl_(app_ctrl)
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(10, 10, 10, 10);
    root->setSpacing(8);

    // NIC stats
    nic_card_ = new NicStatsCard();
    root->addWidget(nic_card_);

    // Frame decode for selected packet
    frame_card_ = new FrameDecodeCard();
    root->addWidget(frame_card_);

    root->addStretch(1);

    counter_refresh_timer_ = new QTimer(this);
    connect(counter_refresh_timer_, &QTimer::timeout,
            this, &NICPhysicalTab::refreshNICCounters);
    counter_refresh_timer_->start(1000);
    refreshNICCounters();

    connect(app_ctrl, &AppController::selectedPacketChanged,
            this, &NICPhysicalTab::onSelectedPacket);
    connect(ctx_mgr, &PacketContextManager::contextChanged,
            this, &NICPhysicalTab::onContextChanged);
}

void NICPhysicalTab::refreshNICCounters()
{
    if (!app_ctrl_) {
        return;
    }

    updateNICCounters(app_ctrl_->getMetricsCopy());
}

void NICPhysicalTab::updateNICCounters(const NetworkMetrics &metrics)
{
    if (!app_ctrl_ || !nic_card_) {
        return;
    }

    auto ifaces = app_ctrl_->getNICModule().listInterfaces();
    if (ifaces.empty()) {
        return;
    }

    auto stats = app_ctrl_->getNICModule().readStats(ifaces.front());
    if (stats.stats.rx_dropped == 0 && stats.stats.tx_dropped == 0) {
        stats.stats.rx_dropped = metrics.dropped_packets.load();
    }
    nic_card_->update(stats);
}

void NICPhysicalTab::onSelectedPacket(std::shared_ptr<const UnifiedPacket> pkt)
{
    if (pkt) frame_card_->setPacket(*pkt);
}

void NICPhysicalTab::onContextChanged(PacketContext ctx)
{
    if (ctx.valid && ctx.packet) {
        setProperty("activePacketId", QVariant::fromValue<qulonglong>(ctx.packet->id));
        onSelectedPacket(ctx.packet);
        return;
    }
    setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
    frame_card_->clearPacket();
}
