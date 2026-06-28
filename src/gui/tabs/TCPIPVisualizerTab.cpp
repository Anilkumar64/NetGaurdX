#include "gui/PacketContextManager.h"
// TCPIPVisualizerTab.cpp
// Step-based TCP/IP encapsulation visualizer.
//
// Visual model (encapsulation direction):
//   Step 0 – Application layer: [ ████████████ PAYLOAD ████████████ ]
//   Step 1 – Transport:         [ TCP → ][ ████ PAYLOAD ████ ]
//   Step 2 – Network:           [ IP → ][ TCP ][ ████ PAYLOAD ████ ]
//   Step 3 – Link:              [ ETH → ][ IP ][ TCP ][ ████ PAYLOAD ████ ]
//
// Each header slides in from the left via a progress value [0…1].
// The payload block stays fixed on the right.

#include "gui/tabs/TCPIPVisualizerTab.h"

#include <QDateTime>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QPainter>
#include <QPainterPath>
#include <QVariant>
#include <QScrollBar>
#include <QSizePolicy>
#include <QSplitter>
#include <QStyle>
#include <QStringList>
#include <QVBoxLayout>
#include <algorithm>
#include <cmath>
#include <array>

#include "core/Logger.h"
#include "gui/UiTheme.h"

// ═════════════════════════════════════════════════════════════════════════════
//  Free helpers
// ═════════════════════════════════════════════════════════════════════════════

namespace {

QColor layerColor(int step) // 0=App 1=Transport 2=Network 3=Link
{
    switch (step) {
    case 0: return QColor(UiTheme::kPayload);
    case 1: return QColor(UiTheme::kTcp);
    case 2: return QColor(UiTheme::kIp);
    case 3: return QColor(UiTheme::kEthernet);
    }
    return QColor(UiTheme::kMuted);
}

QString layerName(int step)
{
    switch (step) {
    case 0: return "Application";
    case 1: return "Transport";
    case 2: return "Network";
    case 3: return "Link";
    }
    return "";
}

QString shortFlags(uint8_t flags)
{
    const QString v = QString::fromStdString(tcpFlagsToString(flags));
    return v.isEmpty() ? "—" : v;
}

QString macToString(const uint8_t mac[6])
{
    return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0],2,16,QChar('0')).arg(mac[1],2,16,QChar('0'))
        .arg(mac[2],2,16,QChar('0')).arg(mac[3],2,16,QChar('0'))
        .arg(mac[4],2,16,QChar('0')).arg(mac[5],2,16,QChar('0'));
}

bool isPrivateIPv4(const std::string &ip)
{
    const QStringList parts = QString::fromStdString(ip).split('.');
    if (parts.size() != 4) return false;
    bool ok;
    int a = parts[0].toInt(&ok); if (!ok) return false;
    int b = parts[1].toInt(&ok); if (!ok) return false;
    return a == 10 || (a == 172 && b >= 16 && b <= 31) ||
           (a == 192 && b == 168) || a == 127 || (a == 169 && b == 254);
}

} // namespace

// ═════════════════════════════════════════════════════════════════════════════
//  StepCanvas  –  the main drawing widget
// ═════════════════════════════════════════════════════════════════════════════
//
//  Layout inside the canvas (left → right):
//
//    ┌─────────────────────────────────────────────────────────────────┐
//    │  TITLE   "Step N/3 – Adding <Layer> header"                     │
//    │  STEP TRACKER  [App] → [Transport] → [Network] → [Link]         │
//    │                                                                 │
//    │  PACKET BAR  (the sliding header blocks + payload)              │
//    │                                                                 │
//    │  LEGEND  ■ Application  ■ Transport  ■ Network  ■ Link          │
//    │                                                                 │
//    │  DETAIL CARD  (field-level info for the currently-active layer) │
//    └─────────────────────────────────────────────────────────────────┘

class TCPIPVisualizerTab::StepCanvas : public QWidget
{
public:
    explicit StepCanvas(QWidget *parent = nullptr) : QWidget(parent)
    {
        setMinimumHeight(340);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }

    // Called once per new packet
    void setPacket(const UnifiedPacket &pkt, const QString &payloadDesc)
    {
        pkt_            = pkt;
        payload_desc_   = payloadDesc;
        has_pkt_        = true;
        step_index_     = 0;
        step_progress_  = 1.0;   // step 0 is fully shown immediately
        update();
    }

    // Called every timer tick or on Step button press
    void setState(int stepIndex, qreal progress)
    {
        step_index_    = stepIndex;
        step_progress_ = std::clamp(progress, 0.0, 1.0);
        update();
    }

    void clear()
    {
        has_pkt_ = false;
        step_index_ = 0;
        step_progress_ = 1.0;
        update();
    }

protected:
    void paintEvent(QPaintEvent *) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        p.fillRect(rect(), QColor(UiTheme::kBackground));

        if (!has_pkt_) {
            drawEmptyState(p);
            return;
        }

        QRectF b = QRectF(rect()).adjusted(18, 14, -18, -14);
        qreal y = b.top();

        drawTitle(p, b, y);           y += 34;
        drawStepTracker(p, b, y);     y += 50;
        drawPacketBar(p, QRectF(b.left(), y, b.width(), 100)); y += 110;
        drawLegend(p, QRectF(b.left(), y, b.width(), 24));    y += 34;
        drawDetailCard(p, QRectF(b.left(), y, b.width(), b.bottom() - y));
    }

private:
    // ── Empty state ────────────────────────────────────────────────────────
    void drawEmptyState(QPainter &p)
    {
        p.setPen(QColor(UiTheme::kMuted));
        QFont f = font(); f.setPointSize(12); f.setItalic(true); p.setFont(f);
        p.drawText(rect(), Qt::AlignCenter,
                   "Select a packet in the stream\nto visualize its encapsulation");
    }

    // ── Title line ─────────────────────────────────────────────────────────
    void drawTitle(QPainter &p, const QRectF &b, qreal y)
    {
        static const char *kVerbs[] = {
            "Step 1 / 4  –  Application layer  (payload originates here)",
            "Step 2 / 4  –  Transport layer  (TCP/UDP header added)",
            "Step 3 / 4  –  Network layer  (IP header added)",
            "Step 4 / 4  –  Link layer  (Ethernet frame complete)",
        };
        QFont f = font(); f.setBold(true); f.setPointSize(11); p.setFont(f);
        p.setPen(layerColor(step_index_));
        p.drawText(QRectF(b.left(), y, b.width(), 28), Qt::AlignLeft | Qt::AlignVCenter,
                   kVerbs[std::clamp(step_index_, 0, 3)]);
    }

    // ── Step tracker pills ─────────────────────────────────────────────────
    void drawStepTracker(QPainter &p, const QRectF &b, qreal y)
    {
        static const char *kNames[] = {"Application", "Transport", "Network", "Link"};
        const qreal pillW = (b.width() - 30) / 4.0;
        const qreal pillH = 30;
        qreal x = b.left();

        for (int i = 0; i <= 3; ++i) {
            QRectF pill(x, y + (40 - pillH) / 2, pillW, pillH);
            bool done    = i < step_index_;
            bool current = i == step_index_;
            bool pending = i > step_index_;

            QColor bg = done    ? layerColor(i).darker(130)
                       : current ? layerColor(i)
                                 : QColor(UiTheme::kPanel);
            QColor border = pending ? QColor(UiTheme::kBorder) : layerColor(i);
            QColor text   = pending ? QColor(UiTheme::kMuted)  : QColor("#06101f");

            p.setPen(QPen(border, current ? 2 : 1));
            p.setBrush(bg);
            p.drawRoundedRect(pill, 6, 6);

            QFont f = font();
            f.setBold(current || done);
            f.setPointSize(current ? 9 : 8);
            p.setFont(f);
            p.setPen(pending ? QColor(UiTheme::kMuted) : text);
            p.drawText(pill, Qt::AlignCenter, kNames[i]);

            // Check / tick for completed steps
            if (done) {
                QFont tick = font(); tick.setBold(true); tick.setPointSize(9);
                p.setFont(tick);
                p.setPen(QColor(UiTheme::kGood));
                p.drawText(QRectF(pill.right() - 18, pill.top() - 8, 16, 16),
                           Qt::AlignCenter, "✓");
            }

            x += pillW;

            // Arrow between pills
            if (i < 3) {
                p.setPen(QPen(QColor(UiTheme::kBorder), 1));
                qreal arrowY = y + 20;
                p.drawLine(QPointF(x, arrowY), QPointF(x + 10, arrowY));
                QPolygonF head;
                head << QPointF(x + 10, arrowY)
                     << QPointF(x + 5,  arrowY - 4)
                     << QPointF(x + 5,  arrowY + 4);
                p.setBrush(QColor(UiTheme::kBorder));
                p.setPen(Qt::NoPen);
                p.drawPolygon(head);
                x += 10;
            }
        }
    }

    // ── Packet bar: headers slide in from left, payload stays fixed ────────
    void drawPacketBar(QPainter &p, const QRectF &rect)
    {
        // Fixed proportions for fully-present headers:
        //   Ethernet: 14%   IP: 10%   TCP/UDP: 10%   Payload: 66%
        // We only SHOW headers up to and including step_index_.
        // The in-progress header (== step_index_) is clipped by step_progress_.

        // Build visible blocks in order they exist in the bar:
        //   [ETH][IP][TCP][PAYLOAD]   — ETH is leftmost
        // We draw from right to left conceptually, keeping payload pinned right.

        struct Block {
            int   step;         // which encapsulation step adds this block
            qreal baseFraction; // fraction of bar width when fully present
            QString title;
            QString detail;
        };

        const bool hasTCP = pkt_.has_tcp;
        const bool hasUDP = pkt_.has_udp;
        QString transportTitle = hasTCP ? "TCP" : hasUDP ? "UDP" : "Transport";
        QString transportDetail = hasTCP
            ? QString(":%1→:%2  %3").arg(pkt_.src_port).arg(pkt_.dst_port).arg(shortFlags(pkt_.tcp_flags))
            : QString(":%1→:%2").arg(pkt_.src_port).arg(pkt_.dst_port);
        QString ipDetail = QString("%1→%2  TTL %3")
            .arg(QString::fromStdString(pkt_.src_ip))
            .arg(QString::fromStdString(pkt_.dst_ip))
            .arg(pkt_.ip_hdr.ttl);
        QString ethDetail = QString("0x%1").arg((int)pkt_.eth_hdr.ethertype, 4, 16, QChar('0'));

        // Blocks in wire order (left → right): ETH, IP, TCP, PAYLOAD
        // But payload is step 0; each header step adds to the left.
        const std::array<Block, 4> blocks {{
            {3, 0.13, "Ethernet", ethDetail},         // Link
            {2, 0.10, "IP",       ipDetail},          // Network
            {1, 0.10, transportTitle, transportDetail},// Transport
            {0, 0.67, "Payload",  payload_desc_.left(60)}, // Application
        }};

        // Compute effective widths: a block at step > step_index_ has width 0.
        // Block at step == step_index_ has width = baseFraction * step_progress_.
        // Renormalise so total = rect.width().

        double totalFraction = 0;
        for (auto &blk : blocks) {
            if (blk.step > step_index_) continue;
            double f = blk.baseFraction;
            if (blk.step == step_index_ && blk.step != 0) // payload always full
                f *= step_progress_;
            totalFraction += f;
        }
        if (totalFraction <= 0) totalFraction = 1;

        // Draw outer border
        p.setPen(QPen(QColor(UiTheme::kBorder), 1));
        p.setBrush(Qt::NoBrush);
        p.drawRoundedRect(rect.adjusted(0.5,0.5,-0.5,-0.5), 8, 8);

        // Draw blocks left → right
        qreal x = rect.left();
        for (int bi = 0; bi < (int)blocks.size(); ++bi) {
            const auto &blk = blocks[bi];
            if (blk.step > step_index_) continue;

            double f = blk.baseFraction;
            if (blk.step == step_index_ && blk.step != 0)
                f *= step_progress_;

            qreal bw = rect.width() * f / totalFraction;
            if (bw < 1) continue;

            QRectF br(x, rect.top(), bw, rect.height());
            QColor fill = layerColor(blk.step);

            // Slide-in effect: clip the header block from its left edge
            // while it's entering. The block is at its natural x position
            // but we clip the painter to reveal it progressively.
            bool isAnimating = (blk.step == step_index_ && blk.step != 0 && step_progress_ < 1.0);

            if (isAnimating) {
                // The block slides in from the left: at progress=0 nothing visible,
                // at progress=1 fully visible. We achieve this by drawing only
                // the rightmost `progress * bw` pixels of the block.
                qreal visiblePx = bw; // already scaled by progress above
                qreal clipLeft  = x; // already at the correct position

                p.save();
                p.setClipRect(QRectF(clipLeft, rect.top(), visiblePx, rect.height()));
            }

            // Fill
            fill.setAlphaF(blk.step == 0 ? 0.85 : 0.95);
            p.setPen(Qt::NoPen);
            p.setBrush(fill);
            p.drawRoundedRect(br.adjusted(2,2,-2,-2), 7, 7);

            // Restore clip
            if (isAnimating) p.restore();

            // Highlight border on the currently-animating block
            if (blk.step == step_index_ && blk.step != 0) {
                p.setPen(QPen(fill.lighter(160), 2));
                p.setBrush(Qt::NoBrush);
                p.drawRoundedRect(br.adjusted(2,2,-2,-2), 7, 7);
            }

            // Labels – only when wide enough
            if (bw > 40) {
                QFont title = font(); title.setBold(true);
                title.setPointSize(bw < 80 ? 8 : 10);
                p.setFont(title);
                p.setPen(QColor("#06101f"));
                p.drawText(br.adjusted(6, 6, -6, -rect.height()/2+4),
                           Qt::AlignCenter | Qt::TextWordWrap, blk.title);
            }
            if (bw > 70) {
                QFont detail = font(); detail.setPointSize(7);
                p.setFont(detail);
                p.setPen(QColor("#06101f").lighter(160));
                p.drawText(br.adjusted(4, rect.height()/2-4, -4, -6),
                           Qt::AlignCenter | Qt::TextWordWrap, blk.detail);
            }

            // Separator line between blocks
            if (bi > 0 && x > rect.left() + 2) {
                p.setPen(QPen(QColor(UiTheme::kBackground).lighter(130), 1));
                p.drawLine(QPointF(x, rect.top()+4), QPointF(x, rect.bottom()-4));
            }

            x += bw;
        }

        // If nothing is visible yet (shouldn't happen) draw placeholder
        if (x <= rect.left() + 2) {
            p.setPen(QColor(UiTheme::kMuted));
            p.drawText(rect, Qt::AlignCenter, "—");
        }
    }

    // ── Legend ─────────────────────────────────────────────────────────────
    void drawLegend(QPainter &p, const QRectF &rect)
    {
        static const char *kNames[] = {"Application", "Transport", "Network", "Link"};
        qreal x = rect.left();
        QFont f = font(); f.setPointSize(8); p.setFont(f);
        for (int i = 0; i <= 3; ++i) {
            bool visible = (i <= step_index_);
            QColor c = layerColor(i);
            if (!visible) c.setAlphaF(0.3);
            p.setPen(Qt::NoPen); p.setBrush(c);
            p.drawRoundedRect(QRectF(x, rect.top()+5, 12, 12), 3, 3);
            p.setPen(visible ? QColor(UiTheme::kText) : QColor(UiTheme::kBorder));
            p.drawText(QRectF(x+16, rect.top(), 94, rect.height()),
                       Qt::AlignVCenter, kNames[i]);
            x += 110;
        }
    }

    // ── Detail card: field-level info for the active layer ─────────────────
    void drawDetailCard(QPainter &p, const QRectF &rect)
    {
        if (rect.height() < 30) return;

        // Background card
        p.setPen(QPen(QColor(UiTheme::kBorder), 1));
        p.setBrush(QColor(UiTheme::kPanel));
        p.drawRoundedRect(rect.adjusted(0.5,0.5,-0.5,-0.5), 8, 8);

        QRectF inner = rect.adjusted(14, 10, -14, -10);

        // Title bar
        QFont bold = font(); bold.setBold(true); bold.setPointSize(9);
        p.setFont(bold);
        p.setPen(layerColor(step_index_));
        p.drawText(inner.left(), inner.top(), inner.width(), 20,
                   Qt::AlignLeft | Qt::AlignVCenter,
                   layerName(step_index_) + " layer — field breakdown");

        // Fields
        QStringList fields = buildFieldLines();
        QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        mono.setPointSize(8);
        p.setFont(mono);
        p.setPen(QColor(UiTheme::kText));

        qreal y = inner.top() + 24;
        for (const QString &line : fields) {
            if (y + 16 > inner.bottom()) {
                p.setPen(QColor(UiTheme::kMuted));
                p.drawText(QRectF(inner.left(), y, inner.width(), 14),
                           Qt::AlignLeft | Qt::AlignVCenter, "…");
                break;
            }
            // Colour the field name
            int colon = line.indexOf(':');
            if (colon > 0) {
                QString key = line.left(colon + 1);
                QString val = line.mid(colon + 1);
                p.setPen(QColor(UiTheme::kMuted));
                QFontMetrics fm(mono);
                p.drawText(QRectF(inner.left(), y, fm.horizontalAdvance(key), 14),
                           Qt::AlignLeft | Qt::AlignVCenter, key);
                p.setPen(QColor(UiTheme::kText));
                p.drawText(QRectF(inner.left() + fm.horizontalAdvance(key), y,
                                  inner.width() - fm.horizontalAdvance(key), 14),
                           Qt::AlignLeft | Qt::AlignVCenter, val);
            } else {
                p.setPen(QColor(UiTheme::kText));
                p.drawText(QRectF(inner.left(), y, inner.width(), 14),
                           Qt::AlignLeft | Qt::AlignVCenter, line);
            }
            y += 16;
        }
    }

    // ── Build field lines for the current step ─────────────────────────────
    QStringList buildFieldLines() const
    {
        QStringList lines;
        switch (step_index_) {
        case 0: // Application
            if (pkt_.has_http) {
                lines << "Protocol: HTTP";
                if (!pkt_.http_info.method.empty())
                    lines << "Method:  " + QString::fromStdString(pkt_.http_info.method)
                               + "  " + QString::fromStdString(pkt_.http_info.url);
                if (!pkt_.http_info.status_code.empty())
                    lines << "Status:  " + QString::fromStdString(pkt_.http_info.status_code);
                if (!pkt_.http_info.body_preview.empty())
                    lines << "Preview: " + QString::fromStdString(pkt_.http_info.body_preview).left(80);
            } else if (pkt_.has_dns) {
                lines << "Protocol: DNS";
                lines << "Query:   " + QString::fromStdString(pkt_.dns_info.query_name);
                if (!pkt_.dns_info.answers.empty())
                    lines << "Answer:  " + QString::fromStdString(pkt_.dns_info.answers.front());
            } else if (pkt_.payload_len == 0) {
                if (pkt_.has_tcp) {
                    lines << "No application payload (TCP control packet)";
                    lines << "Flags:   " + shortFlags(pkt_.tcp_flags);
                    if (pkt_.tcp_flags & 0x02) lines << "         SYN — initiating new connection";
                    if (pkt_.tcp_flags & 0x04) lines << "         RST — connection aborted";
                    if (pkt_.tcp_flags & 0x01) lines << "         FIN — graceful close";
                    if (pkt_.tcp_flags & 0x10) lines << "         ACK — acknowledgement";
                } else if (pkt_.has_icmp) {
                    lines << "Protocol: ICMP (no TCP/UDP payload)";
                    lines << "Type:    " + QString::number(pkt_.icmp_hdr.type);
                    lines << "Code:    " + QString::number(pkt_.icmp_hdr.code);
                } else {
                    lines << "No application payload decoded";
                    lines << "Payload bytes: 0";
                }
            } else {
                lines << "Payload bytes: " + QString::number(pkt_.payload_len);
                // ASCII preview
                QString ascii;
                size_t end = std::min(pkt_.raw_data.size(), pkt_.payload_offset + pkt_.payload_len);
                for (size_t i = pkt_.payload_offset; i < end && ascii.size() < 72; ++i) {
                    char ch = static_cast<char>(pkt_.raw_data[i]);
                    ascii += (ch >= 32 && ch <= 126) ? QChar(ch) : QChar('.');
                }
                lines << "ASCII:   " + ascii;
            }
            break;

        case 1: // Transport
            if (pkt_.has_tcp) {
                lines << "Protocol:  TCP";
                lines << "Src port:  " + QString::number(pkt_.src_port);
                lines << "Dst port:  " + QString::number(pkt_.dst_port);
                lines << "Flags:     " + shortFlags(pkt_.tcp_flags);
                lines << "Seq:       " + QString::number(pkt_.seq_num);
                lines << "Ack:       " + QString::number(pkt_.ack_num);
                lines << "Hdr bytes: " + QString::number(pkt_.transport_len);
            } else if (pkt_.has_udp) {
                lines << "Protocol:  UDP";
                lines << "Src port:  " + QString::number(pkt_.src_port);
                lines << "Dst port:  " + QString::number(pkt_.dst_port);
                lines << "Length:    " + QString::number(pkt_.udp_hdr.length);
                lines << "Hdr bytes: " + QString::number(pkt_.transport_len);
            } else if (pkt_.has_icmp) {
                lines << "Protocol:  ICMP";
                lines << "Type:      " + QString::number(pkt_.icmp_hdr.type);
                lines << "Code:      " + QString::number(pkt_.icmp_hdr.code);
            } else {
                lines << "Transport header not decoded";
            }
            break;

        case 2: // Network
            if (pkt_.has_ip) {
                lines << "Protocol:  IPv4";
                lines << "Src IP:    " + QString::fromStdString(pkt_.src_ip);
                lines << "Dst IP:    " + QString::fromStdString(pkt_.dst_ip);
                lines << "TTL:       " + QString::number(pkt_.ip_hdr.ttl);
                lines << "Length:    " + QString::number(pkt_.ip_hdr.total_length) + " bytes";
                lines << "Proto num: " + QString::number(pkt_.ip_hdr.protocol);
                lines << "Hdr bytes: " + QString::number(pkt_.ip_len);
            } else {
                lines << "IP header not decoded";
            }
            break;

        case 3: // Link
            if (pkt_.has_eth) {
                lines << "Protocol:  Ethernet II";
                lines << "Src MAC:   " + macToString(pkt_.eth_hdr.src);
                lines << "Dst MAC:   " + macToString(pkt_.eth_hdr.dst);
                lines << "Ethertype: 0x" + QString::number(pkt_.eth_hdr.ethertype, 16).rightJustified(4,'0');
                lines << "Hdr bytes: " + QString::number(pkt_.eth_len);
                lines << "Total frm: " + QString::number(pkt_.packet_size) + " bytes";
            } else {
                lines << "Ethernet header not decoded";
            }
            break;
        }
        return lines;
    }

    // ── Members ────────────────────────────────────────────────────────────
    UnifiedPacket pkt_;
    QString       payload_desc_;
    bool          has_pkt_{false};
    int           step_index_{0};
    qreal         step_progress_{1.0};
};

// ═════════════════════════════════════════════════════════════════════════════
//  TCPIPVisualizerTab  –  outer widget (controls + canvas + log)
// ═════════════════════════════════════════════════════════════════════════════

TCPIPVisualizerTab::TCPIPVisualizerTab(AppController *app_ctrl, PacketContextManager *ctx_mgr, QWidget *parent)
    : QWidget(parent)
{
    buildUi();
    // First packet auto-populates before any user click
    connect(app_ctrl, &AppController::packetReceived,
            this, &TCPIPVisualizerTab::onLatestPacket);
    // Every context change (from any source) drives the visualizer
    connect(ctx_mgr, &PacketContextManager::contextChanged,
            this, [this](PacketContext ctx) {
                if (ctx.valid && ctx.packet) {
                    setProperty("activePacketId", QVariant::fromValue<qulonglong>(ctx.packet->id));
                    selectPacket(*ctx.packet);
                    return;
                }

                setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
                has_packet_ = false;
                current_packet_ = UnifiedPacket{};
                setPlaying(false);
                info_label_->setText("Select a packet in the stream to begin.");
                stage_label_->setText("Waiting for packet…");
                canvas_->clear();
                log_view_->clear();
                l2_view_->clear();
                l3_view_->clear();
                l4_view_->clear();
                hex_view_->clear();
            });
}

// ─────────────────────────────────────────────────────────────────────────────
//  buildUi
// ─────────────────────────────────────────────────────────────────────────────

void TCPIPVisualizerTab::buildUi()
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(10, 10, 10, 10);
    root->setSpacing(8);

    // ── Info banner ──────────────────────────────────────────────────────────
    info_label_ = new QLabel("Select a packet in the stream to begin.");
    info_label_->setStyleSheet(
        QString("font-weight:bold; font-size:10pt; color:%1; padding:6px 10px;"
                "background:%2; border:1px solid %3; border-radius:6px;")
            .arg(UiTheme::kText, UiTheme::kPanel, UiTheme::kBorder));
    root->addWidget(info_label_);

    // ── Outer tab widget: Encapsulation | Decoded Details ───────────────────
    outer_tabs_ = new QTabWidget(this);
    root->addWidget(outer_tabs_, 1);

    // ── ① Encapsulation tab ─────────────────────────────────────────────────
    auto *enc_widget = new QWidget();
    auto *enc_layout = new QVBoxLayout(enc_widget);
    enc_layout->setContentsMargins(8, 8, 8, 8);
    enc_layout->setSpacing(8);

    // Controls row
    auto *ctrl = new QHBoxLayout();
    ctrl->setSpacing(6);

    play_btn_  = new QPushButton(style()->standardIcon(QStyle::SP_MediaPlay),  "  Play");
    pause_btn_ = new QPushButton(style()->standardIcon(QStyle::SP_MediaPause), "  Pause");
    step_btn_  = new QPushButton(style()->standardIcon(QStyle::SP_ArrowForward),"  Step →");
    reset_btn_ = new QPushButton(style()->standardIcon(QStyle::SP_BrowserReload)," Reset");

    for (auto *btn : {play_btn_, pause_btn_, step_btn_, reset_btn_})
        btn->setMinimumHeight(34);

    stage_label_ = new QLabel("Waiting for packet…");
    stage_label_->setStyleSheet(
        QString("color:%1; font-weight:600; padding-left:10px;").arg(UiTheme::kMuted));

    ctrl->addWidget(play_btn_);
    ctrl->addWidget(pause_btn_);
    ctrl->addWidget(step_btn_);
    ctrl->addWidget(reset_btn_);
    ctrl->addWidget(stage_label_, 1);
    enc_layout->addLayout(ctrl);

    // Canvas
    canvas_ = new StepCanvas();
    canvas_->setMinimumHeight(320);
    enc_layout->addWidget(canvas_, 1);

    // Log view
    log_view_ = new QTextEdit();
    log_view_->setReadOnly(true);
    log_view_->setMaximumHeight(130);
    log_view_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    log_view_->setStyleSheet(
        QString("background:%1; color:%2; border:1px solid %3; padding:6px;")
            .arg(UiTheme::kPanel, UiTheme::kText, UiTheme::kBorder));
    enc_layout->addWidget(log_view_);

    outer_tabs_->addTab(enc_widget, "Encapsulation  (step-by-step)");

    // ── ② Decoded Details tab ───────────────────────────────────────────────
    auto *det_widget = new QWidget();
    auto *det_layout = new QVBoxLayout(det_widget);
    det_layout->setContentsMargins(8, 8, 8, 8);

    detail_tabs_ = new QTabWidget();
    l2_view_  = new QTextEdit(); l2_view_->setReadOnly(true);
    l3_view_  = new QTextEdit(); l3_view_->setReadOnly(true);
    l4_view_  = new QTextEdit(); l4_view_->setReadOnly(true);
    hex_view_ = new QTextEdit(); hex_view_->setReadOnly(true);

    QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    mono.setPointSize(9);
    for (auto *v : {l2_view_, l3_view_, l4_view_, hex_view_}) {
        v->setFont(mono);
        v->setStyleSheet(
            QString("background:%1; color:%2; border:1px solid %3;")
                .arg(UiTheme::kPanel, UiTheme::kText, UiTheme::kBorder));
    }

    detail_tabs_->addTab(l2_view_,  "L2 – Ethernet");
    detail_tabs_->addTab(l3_view_,  "L3 – IP");
    detail_tabs_->addTab(l4_view_,  "L4 / L7");
    detail_tabs_->addTab(hex_view_, "Hex dump");
    det_layout->addWidget(detail_tabs_);

    outer_tabs_->addTab(det_widget, "Decoded Details");

    // ── Wire up controls ────────────────────────────────────────────────────
    timer_ = new QTimer(this);
    timer_->setInterval(kTickMs);

    connect(timer_,      &QTimer::timeout,        this, &TCPIPVisualizerTab::onTimerTick);
    connect(play_btn_,   &QPushButton::clicked,   this, [this]{
        if (!has_packet_) return;
        single_step_ = false;
        setPlaying(true);
    });
    connect(pause_btn_,  &QPushButton::clicked,   this, [this]{
        single_step_ = false;
        setPlaying(false);
    });
    connect(step_btn_,   &QPushButton::clicked,   this, [this]{
        if (!has_packet_) return;
        setPlaying(false);
        // Snap current in-progress step to complete, then advance
        if (step_progress_ < 1.0) {
            // finish the current step instantly
            step_progress_ = 1.0;
            canvas_->setState(step_index_, 1.0);
            updateStageLabel();
        } else if (step_index_ < kMaxStep) {
            // advance to next step instantly
            ++step_index_;
            step_progress_ = 1.0;
            canvas_->setState(step_index_, 1.0);
            commitStep();
        }
        // If already at max, do nothing
    });
    connect(reset_btn_,  &QPushButton::clicked,   this, &TCPIPVisualizerTab::resetToStep0);

    pause_btn_->setEnabled(false);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Slots
// ─────────────────────────────────────────────────────────────────────────────

void TCPIPVisualizerTab::onLatestPacket(std::shared_ptr<const UnifiedPacket> pkt)
{
    Logger::instance().log(LogLevel::DEBUG, "GUI", "TCPIPVisualizerTab::onLatestPacket");
    if (!pkt) return;
    // Dereference at the slot boundary: current_packet_ is a single working copy
    // used only for rendering this tab — not a growing buffer, so one copy is fine.
    if (!has_packet_)
        selectPacket(*pkt);
}

void TCPIPVisualizerTab::selectPacket(UnifiedPacket pkt)
{
    Logger::instance().log(LogLevel::DEBUG, "GUI", "TCPIPVisualizerTab::selectPacket");
    current_packet_ = pkt;
    has_packet_     = true;

    // Build the info banner
    const bool inferredIn = pkt.direction == Direction::UNKNOWN &&
                            isPrivateIPv4(pkt.dst_ip) && !isPrivateIPv4(pkt.src_ip);
    QString dir = (pkt.direction == Direction::TX) ? "TX (outgoing)"
                : (pkt.direction == Direction::RX || inferredIn) ? "RX (incoming)"
                                                                 : "direction unknown";
    QString proto = QString::fromStdString(protocolToString(pkt.protocol));
    QString flags;
    if (pkt.has_tcp && pkt.payload_len == 0)
        flags = "  [" + shortFlags(pkt.tcp_flags) + "]";

    info_label_->setText(
        QString("▶  Packet #%1  |  %2  |  %3  |  %4:%5 → %6:%7%8")
            .arg(pkt.id).arg(proto).arg(dir)
            .arg(QString::fromStdString(pkt.src_ip)).arg(pkt.src_port)
            .arg(QString::fromStdString(pkt.dst_ip)).arg(pkt.dst_port)
            .arg(flags));

    // Reset and arm the canvas with the new packet
    canvas_->setPacket(pkt, describePayload());
    populateDetails();
    resetToStep0();

    // Auto-play after a short delay so the user sees step 0 first
    QTimer::singleShot(600, this, [this]{
        if (has_packet_ && !playing_)
            setPlaying(true);
    });
}

// ─────────────────────────────────────────────────────────────────────────────
//  Animation control
// ─────────────────────────────────────────────────────────────────────────────

void TCPIPVisualizerTab::resetToStep0()
{
    setPlaying(false);
    step_index_    = 0;
    step_progress_ = 1.0;
    single_step_   = false;
    log_view_->clear();

    canvas_->setState(0, 1.0);
    appendLog("APP", "Application layer — payload originates here");
    updateStageLabel();
}

void TCPIPVisualizerTab::setPlaying(bool playing)
{
    playing_ = playing && has_packet_;
    if (playing_) {
        // If we're already at the last step fully complete, restart from 0
        if (step_index_ >= kMaxStep && step_progress_ >= 1.0)
            resetToStep0();
        timer_->start();
    } else {
        timer_->stop();
    }
    play_btn_->setEnabled(!playing_);
    pause_btn_->setEnabled(playing_);
}

void TCPIPVisualizerTab::onTimerTick()
{
    if (!playing_ || !has_packet_) return;

    // We are animating step `step_index_` sliding in.
    // Step 0 (payload) is never animated — it starts fully visible.
    if (step_index_ == 0 && step_progress_ >= 1.0) {
        // Immediately start step 1
        step_index_    = 1;
        step_progress_ = 0.0;
        appendLog("TRANSPORT", "Adding Transport layer header…");
    }

    step_progress_ = std::min(1.0, step_progress_ + kSpeedPerTick);
    canvas_->setState(step_index_, step_progress_);
    updateStageLabel();

    if (step_progress_ >= 1.0) {
        // This step is complete
        commitStep();

        if (step_index_ >= kMaxStep) {
            // All steps done
            setPlaying(false);
            single_step_ = false;
            appendLog("DONE", "Encapsulation complete — full Ethernet frame ready");
            return;
        }

        if (single_step_) {
            setPlaying(false);
            single_step_ = false;
            return;
        }

        // Advance to next step
        ++step_index_;
        step_progress_ = 0.0;
        logStepStart(step_index_);
    }
}

void TCPIPVisualizerTab::commitStep()
{
    // Log completion of step_index_
    static const char *kDone[] = {
        "Application payload ready",
        "Transport header attached",
        "Network header attached",
        "Link header attached — full frame assembled",
    };
    if (step_index_ >= 0 && step_index_ <= 3)
        appendLog(layerName(step_index_).toUpper().toStdString().c_str(),
                  kDone[step_index_]);
}

void TCPIPVisualizerTab::logStepStart(int step)
{
    switch (step) {
    case 1: appendLog("TRANSPORT", "Wrapping payload in TCP/UDP header…"); break;
    case 2: appendLog("NETWORK",   "Wrapping segment in IP header…"); break;
    case 3: appendLog("LINK",      "Wrapping datagram in Ethernet frame…"); break;
    default: break;
    }
}

void TCPIPVisualizerTab::updateStageLabel()
{
    if (!has_packet_) { stage_label_->setText("Waiting for packet…"); return; }

    static const char *kStages[] = {
        "Step 1/4 — Application payload",
        "Step 2/4 — Adding Transport header",
        "Step 3/4 — Adding Network header",
        "Step 4/4 — Adding Link header",
    };
    int pct = static_cast<int>(step_progress_ * 100);
    QString stage = kStages[std::clamp(step_index_, 0, 3)];
    stage_label_->setText(step_progress_ >= 1.0
                              ? stage + "  ✓"
                              : stage + QString("  %1%").arg(pct));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Decoded-details tab population
// ─────────────────────────────────────────────────────────────────────────────

void TCPIPVisualizerTab::populateDetails()
{
    const UnifiedPacket &pkt = current_packet_;

    // L2
    l2_view_->setText(
        QString("═══ Ethernet (Layer 2) ═══\n"
                "Present:    %1\n"
                "Src MAC:    %2\n"
                "Dst MAC:    %3\n"
                "Ethertype:  0x%4\n"
                "Header len: %5 bytes\n"
                "Offset:     %6")
            .arg(pkt.has_eth ? "yes" : "no")
            .arg(macToString(pkt.eth_hdr.src))
            .arg(macToString(pkt.eth_hdr.dst))
            .arg(pkt.eth_hdr.ethertype, 4, 16, QChar('0'))
            .arg(pkt.eth_len)
            .arg(pkt.eth_offset));

    // L3
    l3_view_->setText(
        QString("═══ IPv4 (Layer 3) ═══\n"
                "Present:      %1\n"
                "Src IP:       %2\n"
                "Dst IP:       %3\n"
                "TTL:          %4\n"
                "Total length: %5 bytes\n"
                "Protocol num: %6\n"
                "Header len:   %7 bytes")
            .arg(pkt.has_ip ? "yes" : "no")
            .arg(QString::fromStdString(pkt.src_ip))
            .arg(QString::fromStdString(pkt.dst_ip))
            .arg(pkt.ip_hdr.ttl)
            .arg(pkt.ip_hdr.total_length)
            .arg(pkt.ip_hdr.protocol)
            .arg(pkt.ip_len));

    // L4 / L7
    QString l4;
    if (pkt.has_tcp) {
        l4 = QString("═══ TCP (Layer 4) ═══\n"
                     "Src port:   %1\n"
                     "Dst port:   %2\n"
                     "Flags:      %3\n"
                     "Seq:        %4\n"
                     "Ack:        %5\n"
                     "Header len: %6 bytes\n"
                     "Payload:    %7 bytes\n")
                 .arg(pkt.src_port).arg(pkt.dst_port)
                 .arg(shortFlags(pkt.tcp_flags))
                 .arg(pkt.seq_num).arg(pkt.ack_num)
                 .arg(pkt.transport_len).arg(pkt.payload_len);

        if (pkt.payload_len == 0) {
            l4 += "\n[Control packet — no application payload]\n";
            if (pkt.tcp_flags & 0x02) l4 += "SYN: connection is being initiated\n";
            if (pkt.tcp_flags & 0x10) l4 += "ACK: acknowledgement\n";
            if (pkt.tcp_flags & 0x04) l4 += "RST: connection reset — endpoint refused or crashed\n";
            if (pkt.tcp_flags & 0x01) l4 += "FIN: graceful connection close\n";
        }
    } else if (pkt.has_udp) {
        l4 = QString("═══ UDP (Layer 4) ═══\n"
                     "Src port:   %1\n"
                     "Dst port:   %2\n"
                     "Length:     %3\n"
                     "Payload:    %4 bytes\n")
                 .arg(pkt.src_port).arg(pkt.dst_port)
                 .arg(pkt.udp_hdr.length).arg(pkt.payload_len);
    } else if (pkt.has_icmp) {
        l4 = QString("═══ ICMP ═══\n"
                     "Type:  %1\n"
                     "Code:  %2\n")
                 .arg(pkt.icmp_hdr.type).arg(pkt.icmp_hdr.code);
    }

    if (pkt.has_http) {
        l4 += QString("\n═══ HTTP (Layer 7) ═══\n"
                      "Method:  %1\n"
                      "URL:     %2\n"
                      "Version: %3\n"
                      "Status:  %4\n"
                      "Body:    %5\n")
                  .arg(QString::fromStdString(pkt.http_info.method))
                  .arg(QString::fromStdString(pkt.http_info.url))
                  .arg(QString::fromStdString(pkt.http_info.version))
                  .arg(QString::fromStdString(pkt.http_info.status_code))
                  .arg(QString::fromStdString(pkt.http_info.body_preview));
    }
    if (pkt.has_dns) {
        l4 += "\n═══ DNS (Layer 7) ═══\n";
        l4 += "Query:   " + QString::fromStdString(pkt.dns_info.query_name) + "\n";
        for (auto &ans : pkt.dns_info.answers)
            l4 += "Answer:  " + QString::fromStdString(ans) + "\n";
    }
    l4_view_->setText(l4.trimmed());

    // Hex dump
    hex_view_->setText(formatHex(0, pkt.raw_data.size(), 256));
}

// ─────────────────────────────────────────────────────────────────────────────
//  Helpers
// ─────────────────────────────────────────────────────────────────────────────

void TCPIPVisualizerTab::appendLog(const QString &layer, const QString &msg)
{
    const QString ts = QDateTime::currentDateTime().toString("HH:mm:ss.zzz");
    log_view_->append(
        QString("<span style='color:%1'>[%2]</span> "
                "<span style='color:%3; font-weight:bold'>[%4]</span> "
                "<span style='color:%5'>%6</span>")
            .arg(UiTheme::kMuted).arg(ts)
            .arg(UiTheme::kAccent).arg(layer.leftJustified(10))
            .arg(UiTheme::kText).arg(msg.toHtmlEscaped()));
    log_view_->verticalScrollBar()->setValue(
        log_view_->verticalScrollBar()->maximum());
}

QString TCPIPVisualizerTab::describePayload() const
{
    const UnifiedPacket &pkt = current_packet_;
    if (pkt.has_http) {
        QString s;
        if (!pkt.http_info.method.empty())
            s += QString::fromStdString(pkt.http_info.method) + " "
               + QString::fromStdString(pkt.http_info.url) + "\n";
        if (!pkt.http_info.status_code.empty())
            s += "HTTP " + QString::fromStdString(pkt.http_info.status_code) + "\n";
        if (!pkt.http_info.body_preview.empty())
            s += QString::fromStdString(pkt.http_info.body_preview);
        return s.trimmed().isEmpty() ? "HTTP payload" : s.trimmed();
    }
    if (pkt.has_dns) {
        return "DNS: " + QString::fromStdString(pkt.dns_info.query_name);
    }
    if (pkt.payload_len == 0) {
        if (pkt.has_tcp)
            return QString("TCP control packet [%1]\nNo application payload").arg(shortFlags(pkt.tcp_flags));
        if (pkt.has_icmp)
            return "ICMP — no application payload";
        return "No payload";
    }
    // Raw ASCII preview
    QString ascii;
    size_t end = std::min(pkt.raw_data.size(), pkt.payload_offset + pkt.payload_len);
    for (size_t i = pkt.payload_offset; i < end && ascii.size() < 120; ++i) {
        char ch = static_cast<char>(pkt.raw_data[i]);
        ascii += (ch >= 32 && ch <= 126) ? QChar(ch) : QChar('.');
    }
    return ascii;
}

QString TCPIPVisualizerTab::formatHex(size_t offset, size_t len, size_t limit) const
{
    const UnifiedPacket &pkt = current_packet_;
    QString out;
    size_t end = std::min(pkt.raw_data.size(), offset + std::min(len, limit));
    for (size_t i = offset; i < end; i += 16) {
        out += QString("%1  ").arg((quint64)i, 4, 16, QChar('0'));
        QString ascii;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < end) {
                uint8_t b = pkt.raw_data[i+j];
                out += QString("%1 ").arg((int)b, 2, 16, QChar('0'));
                ascii += (b >= 32 && b <= 126) ? QChar((char)b) : QChar('.');
            } else {
                out += "   ";
                ascii += " ";
            }
            if (j == 7) out += " ";
        }
        out += "  " + ascii + "\n";
    }
    if (offset + len > end) out += "…";
    return out.trimmed();
}
