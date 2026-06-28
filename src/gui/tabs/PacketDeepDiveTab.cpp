#include "gui/tabs/PacketDeepDiveTab.h"
#include "gui/UiTheme.h"
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QPainter>
#include <QScrollArea>
#include <QStringList>
#include <QVBoxLayout>
#include <QVariant>

namespace {
QString flagsText(const UnifiedPacket &pkt) {
  return pkt.has_tcp ? QString::fromStdString(tcpFlagsToString(pkt.tcp_flags))
                     : "—";
}
QString macStr(const uint8_t mac[6]) {
  return QString("%1:%2:%3:%4:%5:%6")
      .arg(mac[0], 2, 16, QChar('0'))
      .arg(mac[1], 2, 16, QChar('0'))
      .arg(mac[2], 2, 16, QChar('0'))
      .arg(mac[3], 2, 16, QChar('0'))
      .arg(mac[4], 2, 16, QChar('0'))
      .arg(mac[5], 2, 16, QChar('0'));
}

// Styled field row builder for decode views
QString fieldRow(const QString &key, const QString &val,
                 const QString &accent = "") {
  QString color = accent.isEmpty() ? UiTheme::kText : accent;
  return QString("<tr>"
                 "<td style='color:%3; font-size:8pt; padding:3px 10px 3px 0; "
                 "white-space:nowrap; font-weight:700;'>%1</td>"
                 "<td style='color:%2; font-size:9pt; padding:3px 0; "
                 "font-family:monospace;'>%3</td>"
                 "</tr>")
      .arg(key, val, color)
      .replace("%3", color) // fix double use
      // redo properly:
      ;
}

QString makeTable(const QString &title, const QString &titleColor,
                  const QList<QPair<QString, QString>> &fields,
                  const QString &noteColor = "") {
  QString html =
      QString("<div style='margin-bottom:14px;'>"
              "<div style='color:%2; font-size:8pt; font-weight:800; "
              "letter-spacing:1px;"
              " padding:5px 10px; background:#0e1c30; border-left:3px solid %2;"
              " border-radius:3px; margin-bottom:6px;'>%1</div>"
              "<table style='width:100%; border-collapse:collapse;'>")
          .arg(title, titleColor);

  for (const auto &f : fields) {
    bool isWarn = f.second.contains("⚠");
    QString valColor = isWarn ? UiTheme::kWarn : UiTheme::kText;
    html +=
        QString("<tr>"
                "<td style='color:%3; font-size:8pt; padding:3px 16px 3px 8px;"
                " white-space:nowrap; font-weight:700; width:140px;'>%1</td>"
                "<td style='color:%4; font-size:9pt; padding:3px 0; "
                "font-family:monospace;'>%2</td>"
                "</tr>")
            .arg(f.first, f.second, QString(UiTheme::kMuted), valColor);
  }

  html += "</table></div>";
  return html;
}
} // namespace

PacketDeepDiveTab::PacketDeepDiveTab(AppController *app_ctrl,
                                     PacketContextManager *ctx_mgr,
                                     QWidget *parent)
    : QWidget(parent) {
  (void)app_ctrl;

  auto *root = new QVBoxLayout(this);
  root->setContentsMargins(12, 12, 12, 12);
  root->setSpacing(8);

  // ── Summary banner ────────────────────────────────────────────────────
  summary_label_ =
      new QLabel("Select a packet in the stream to inspect decoded layers.");
  summary_label_->setWordWrap(true);
  summary_label_->setStyleSheet(
      QString("font-weight:800; font-size:10pt; color:%1; padding:11px 14px;"
              "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 "
              "#0f1e35,stop:1 #091624);"
              "border-left: 3px solid %1; border-radius:6px;")
          .arg(UiTheme::kAccent));
  root->addWidget(summary_label_);

  // ── Flow info bar ──────────────────────────────────────────────────────
  flow_label_ = new QLabel("Flow: —");
  flow_label_->setStyleSheet(
      QString("font-size:8pt; color:%1; padding:6px 12px;"
              "background:%2; border:1px solid %3; border-radius:5px;"
              "font-family: monospace;")
          .arg(UiTheme::kMuted, UiTheme::kPanelAlt, UiTheme::kBorder));
  root->addWidget(flow_label_);

  // ── Decode tabs ────────────────────────────────────────────────────────
  detail_tabs_ = new QTabWidget();
  detail_tabs_->setStyleSheet(
      QString(
          "QTabBar::tab { padding:7px 16px; font-size:8pt; font-weight:700; }"
          "QTabBar::tab:selected { border-top: 2px solid %1; }")
          .arg(UiTheme::kAccent));

  l2_view_ = new QTextEdit();
  l3_view_ = new QTextEdit();
  l4_view_ = new QTextEdit();
  hex_view_ = new QTextEdit();

  QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
  mono.setPointSize(9);

  for (auto *v : {l2_view_, l3_view_, l4_view_, hex_view_}) {
    v->setReadOnly(true);
    v->setFont(mono);
    v->setStyleSheet(
        QString("background:#080f1c; color:%1; border:none; padding:8px;")
            .arg(UiTheme::kText));
  }
  // Rich text views use HTML
  l2_view_->setAcceptRichText(true);
  l3_view_->setAcceptRichText(true);
  l4_view_->setAcceptRichText(true);

  detail_tabs_->addTab(l2_view_, "⬡  L2 Ethernet");
  detail_tabs_->addTab(l3_view_, "◈  L3 IP");
  detail_tabs_->addTab(l4_view_, "◉  L4 / L7");
  detail_tabs_->addTab(hex_view_, "⬛  Hex Dump");
  root->addWidget(detail_tabs_, 1);

  connect(ctx_mgr, &PacketContextManager::contextChanged, this,
          &PacketDeepDiveTab::onContextChanged);
}

void PacketDeepDiveTab::onContextChanged(PacketContext ctx) {
  if (!ctx.valid || !ctx.packet) {
    setProperty("activePacketId", QVariant::fromValue<qulonglong>(0));
    summary_label_->setText(
        "Select a packet in the stream to inspect decoded layers.");
    flow_label_->setText("Flow: —");
    l2_view_->clear();
    l3_view_->clear();
    l4_view_->clear();
    hex_view_->clear();
    return;
  }
  setProperty("activePacketId",
              QVariant::fromValue<qulonglong>(ctx.packet->id));
  renderPacket(*ctx.packet, ctx.flow);
}

void PacketDeepDiveTab::renderPacket(const UnifiedPacket &pkt,
                                     const std::optional<Flow> &flow) {
  // ── Summary banner ────────────────────────────────────────────────────
  QString meaning;
  QString bannerColor = UiTheme::kAccent;
  if (pkt.has_tcp) {
    if (pkt.tcp_flags & 0x04) {
      meaning = "⚠ RST — connection aborted";
      bannerColor = UiTheme::kBad;
    } else if ((pkt.tcp_flags & 0x12) == 0x12) {
      meaning = "✓ SYN-ACK — handshake response";
      bannerColor = UiTheme::kGood;
    } else if (pkt.tcp_flags & 0x02) {
      meaning = "→ SYN — connection initiating";
      bannerColor = UiTheme::kGood;
    } else if (pkt.tcp_flags & 0x01) {
      meaning = "✓ FIN — graceful close";
      bannerColor = UiTheme::kWarn;
    } else if (pkt.payload_len == 0) {
      meaning = "· ACK / keepalive";
    } else
      meaning = QString("↓ %1 B payload").arg(pkt.payload_len);
  }

  summary_label_->setText(
      QString("▶  #%1  ·  %2  ·  %3:%4 → %5:%6  ·  %7 B  ·  flow %8    %9")
          .arg(pkt.id)
          .arg(QString::fromStdString(protocolToString(pkt.protocol)))
          .arg(QString::fromStdString(pkt.src_ip))
          .arg(pkt.src_port)
          .arg(QString::fromStdString(pkt.dst_ip))
          .arg(pkt.dst_port)
          .arg(pkt.packet_size)
          .arg(pkt.flow_id)
          .arg(meaning));
  summary_label_->setStyleSheet(
      QString("font-weight:800; font-size:10pt; color:%1; padding:11px 14px;"
              "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 "
              "#0f1e35,stop:1 #091624);"
              "border-left: 3px solid %1; border-radius:6px;")
          .arg(bannerColor));

  // ── Flow bar ──────────────────────────────────────────────────────────
  if (flow.has_value()) {
    const auto &f = *flow;
    flow_label_->setText(
        QString("  Flow %1  ·  %2  ·  %3 pkts  ·  %4 B  ·  RTT %5 ms  ·  retx "
                "%6  ·  %7")
            .arg(f.flow_id)
            .arg(QString::fromStdString(protocolToString(f.key.protocol)))
            .arg(f.stats.packet_count)
            .arg(f.stats.byte_count)
            .arg(f.stats.rtt_ms, 0, 'f', 1)
            .arg(f.stats.retransmissions)
            .arg(QString::fromStdString(tcpStateToString(f.tcp_state))));
  } else {
    flow_label_->setText(
        QString("  Flow %1  ·  (no flow record yet)").arg(pkt.flow_id));
  }

  // ── L2 HTML ───────────────────────────────────────────────────────────
  QString l2html =
      "<html><body style='background:#080f1c; margin:0; padding:0;'>";
  l2html +=
      makeTable("⬡  ETHERNET  —  LAYER 2", UiTheme::kEthernet,
                {
                    {"Present", pkt.has_eth ? "yes" : "no"},
                    {"Src MAC", macStr(pkt.eth_hdr.src)},
                    {"Dst MAC", macStr(pkt.eth_hdr.dst)},
                    {"Ethertype", QString("0x%1").arg(pkt.eth_hdr.ethertype, 4,
                                                      16, QChar('0'))},
                    {"Header len", QString("%1 bytes").arg(pkt.eth_len)},
                    {"Offset", QString("%1").arg(pkt.eth_offset)},
                });
  l2html += "</body></html>";
  l2_view_->setHtml(l2html);

  // ── L3 HTML ───────────────────────────────────────────────────────────
  QString l3html =
      "<html><body style='background:#080f1c; margin:0; padding:0;'>";
  QString ttlVal = QString("%1").arg(pkt.ip_hdr.ttl);
  if (pkt.ip_hdr.ttl < 5)
    ttlVal += "  ⚠ near expiry";

  if (pkt.has_ipv6) {
    l3html += makeTable(
        "◈  IPv6  —  LAYER 3", UiTheme::kIp,
        {
            {"Present", "yes — IPv6"},
            {"Src IP", QString::fromStdString(pkt.src_ip)},
            {"Dst IP", QString::fromStdString(pkt.dst_ip)},
            {"Hop limit", QString("%1").arg(pkt.ipv6_hdr.hop_limit)},
            {"Payload len",
             QString("%1 bytes").arg(pkt.ipv6_hdr.payload_length)},
            {"Next header", QString("%1").arg(pkt.ipv6_hdr.next_header)},
        });
  } else {
    l3html += makeTable(
        "◈  IPv4  —  LAYER 3", UiTheme::kIp,
        {
            {"Present", pkt.has_ip ? "yes" : "no"},
            {"Src IP", QString::fromStdString(pkt.src_ip)},
            {"Dst IP", QString::fromStdString(pkt.dst_ip)},
            {"TTL", ttlVal},
            {"Total length", QString("%1 bytes").arg(pkt.ip_hdr.total_length)},
            {"Protocol", QString("%1").arg(pkt.ip_hdr.protocol)},
            {"Header len", QString("%1 bytes").arg(pkt.ip_len)},
            {"Checksum",
             QString("0x%1").arg(pkt.ip_hdr.checksum, 4, 16, QChar('0'))},
        });
  }
  l3html += "</body></html>";
  l3_view_->setHtml(l3html);

  // ── L4/L7 HTML ────────────────────────────────────────────────────────
  QString l4html =
      "<html><body style='background:#080f1c; margin:0; padding:0;'>";

  if (pkt.has_tcp) {
    QList<QPair<QString, QString>> fields = {
        {"Src port", QString("%1").arg(pkt.src_port)},
        {"Dst port", QString("%1").arg(pkt.dst_port)},
        {"Flags", flagsText(pkt)},
        {"Seq", QString("%1").arg(pkt.seq_num)},
        {"Ack", QString("%1").arg(pkt.ack_num)},
        {"Header len", QString("%1 bytes").arg(pkt.transport_len)},
        {"Payload", QString("%1 bytes").arg(pkt.payload_len)},
        {"Window", QString("%1").arg(pkt.tcp_hdr.window)},
    };
    if (pkt.payload_len == 0) {
      QString ctrl;
      if (pkt.tcp_flags & 0x02)
        ctrl += "SYN ";
      if (pkt.tcp_flags & 0x10)
        ctrl += "ACK ";
      if (pkt.tcp_flags & 0x04)
        ctrl += "RST ";
      if (pkt.tcp_flags & 0x01)
        ctrl += "FIN ";
      fields.append({"Control", ctrl.trimmed()});
    }
    l4html += makeTable("◉  TCP  —  LAYER 4", UiTheme::kTcp, fields);
  } else if (pkt.has_udp) {
    l4html +=
        makeTable("◉  UDP  —  LAYER 4", UiTheme::kTcp,
                  {
                      {"Src port", QString("%1").arg(pkt.src_port)},
                      {"Dst port", QString("%1").arg(pkt.dst_port)},
                      {"Length", QString("%1 bytes").arg(pkt.udp_hdr.length)},
                      {"Payload", QString("%1 bytes").arg(pkt.payload_len)},
                      {"Checksum", QString("0x%1").arg(pkt.udp_hdr.checksum, 4,
                                                       16, QChar('0'))},
                  });
  } else if (pkt.has_icmp) {
    l4html +=
        makeTable("◉  ICMP", UiTheme::kTcp,
                  {
                      {"Type", QString("%1").arg(pkt.icmp_hdr.type)},
                      {"Code", QString("%1").arg(pkt.icmp_hdr.code)},
                      {"Payload", QString("%1 bytes").arg(pkt.payload_len)},
                  });
  }

  if (pkt.has_http) {
    l4html += makeTable(
        "◈  HTTP  —  LAYER 7", UiTheme::kPayload,
        {
            {"Method", QString::fromStdString(pkt.http_info.method)},
            {"URL", QString::fromStdString(pkt.http_info.url)},
            {"Version", QString::fromStdString(pkt.http_info.version)},
            {"Status", QString::fromStdString(pkt.http_info.status_code)},
            {"Body", QString::fromStdString(pkt.http_info.body_preview)},
        });
  }
  if (pkt.has_https && pkt.tls_info.sni_hostname.size() > 0) {
    l4html += makeTable(
        "◈  TLS  —  LAYER 7", UiTheme::kGood,
        {
            {"SNI hostname", QString::fromStdString(pkt.tls_info.sni_hostname)},
        });
  }
  if (pkt.has_dns) {
    QList<QPair<QString, QString>> dnsFields;
    dnsFields.append(
        {"Query", QString::fromStdString(pkt.dns_info.query_name)});
    dnsFields.append(
        {"ID", QString("0x%1").arg(pkt.dns_hdr.id, 4, 16, QChar('0'))});
    for (const auto &a : pkt.dns_info.answers)
      dnsFields.append({"Answer", QString::fromStdString(a)});
    l4html += makeTable("◈  DNS  —  LAYER 7", UiTheme::kWarn, dnsFields);
  }

  l4html += "</body></html>";
  l4_view_->setHtml(l4html);

  // ── Hex dump ──────────────────────────────────────────────────────────
  hex_view_->setPlainText(formatHex(pkt));
}

QString PacketDeepDiveTab::formatHex(const UnifiedPacket &pkt) const {
  if (pkt.raw_data.empty())
    return "(raw bytes not retained — header-only packet after parse "
           "optimisation)";

  QString out;
  const size_t limit = std::min(pkt.raw_data.size(), size_t(512));
  for (size_t i = 0; i < limit; i += 16) {
    out += QString("%1  ").arg((quint64)i, 4, 16, QChar('0'));
    QString ascii;
    for (size_t j = 0; j < 16; ++j) {
      if (i + j < limit) {
        uint8_t b = pkt.raw_data[i + j];
        out += QString("%1 ").arg((int)b, 2, 16, QChar('0'));
        ascii += (b >= 32 && b <= 126) ? QChar((char)b) : QChar('.');
      } else {
        out += "   ";
        ascii += ' ';
      }
      if (j == 7)
        out += ' ';
    }
    out += "  " + ascii + '\n';
  }
  if (pkt.raw_data.size() > limit)
    out +=
        QString("\n… %1 more bytes not shown").arg(pkt.raw_data.size() - limit);
  return out.trimmed();
}