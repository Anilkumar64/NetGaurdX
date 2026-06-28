#pragma once

#include <QString>

namespace UiTheme
{
inline constexpr const char* kBackground = "#08111f";
inline constexpr const char* kPanel = "#101b2d";
inline constexpr const char* kPanelAlt = "#13223a";
inline constexpr const char* kBorder = "#25344d";
inline constexpr const char* kText = "#e5edf7";
inline constexpr const char* kMuted = "#91a4bd";
inline constexpr const char* kAccent = "#38bdf8";
inline constexpr const char* kGood = "#22c55e";
inline constexpr const char* kWarn = "#f59e0b";
inline constexpr const char* kBad = "#ef4444";
inline constexpr const char* kPayload = "#2dd4bf";
inline constexpr const char* kTcp = "#f59e0b";
inline constexpr const char* kIp = "#60a5fa";
inline constexpr const char* kEthernet = "#a78bfa";

inline QString appStyleSheet()
{
    return QString(R"(
        QMainWindow, QWidget {
            background: %1;
            color: %5;
            font-family: "Segoe UI", "Inter", Arial, sans-serif;
            font-size: 10pt;
        }
        QToolBar {
            background: %2;
            border: 0;
            border-bottom: 1px solid %4;
            spacing: 8px;
            padding: 8px;
        }
        QStatusBar {
            background: %2;
            border-top: 1px solid %4;
            color: %6;
        }
        QTabWidget::pane {
            border: 1px solid %4;
            top: -1px;
        }
        QTabBar::tab {
            background: %2;
            color: %6;
            padding: 10px 14px;
            border: 1px solid %4;
            border-bottom: 0;
            min-width: 120px;
        }
        QTabBar::tab:selected {
            background: %3;
            color: %5;
            border-top: 2px solid %7;
        }
        QPushButton {
            background: %3;
            color: %5;
            border: 1px solid %4;
            border-radius: 6px;
            padding: 7px 12px;
            font-weight: 600;
        }
        QPushButton:hover {
            border-color: %7;
        }
        QPushButton:disabled {
            color: #52657f;
            background: #0b1424;
        }
        QLineEdit, QComboBox, QTextEdit, QTableWidget {
            background: %2;
            color: %5;
            border: 1px solid %4;
            border-radius: 6px;
            selection-background-color: %7;
            selection-color: #06101f;
        }
        QLineEdit, QComboBox {
            padding: 7px;
        }
        QHeaderView::section {
            background: %3;
            color: %6;
            border: 0;
            border-right: 1px solid %4;
            border-bottom: 1px solid %4;
            padding: 8px;
            font-weight: 700;
        }
        QTableWidget {
            gridline-color: %4;
            alternate-background-color: #0c1728;
        }
        QProgressBar {
            background: %2;
            color: %5;
            border: 1px solid %4;
            border-radius: 6px;
            text-align: center;
            min-height: 18px;
        }
        QProgressBar::chunk {
            background: %7;
            border-radius: 5px;
        }
    )")
        .arg(kBackground, kPanel, kPanelAlt, kBorder, kText, kMuted, kAccent);
}

inline QString panelStyle()
{
    return QString("background:%1; border:1px solid %2; border-radius:8px; color:%3;")
        .arg(kPanel, kBorder, kText);
}

inline QString mutedLabelStyle()
{
    return QString("color:%1;").arg(kMuted);
}
}
