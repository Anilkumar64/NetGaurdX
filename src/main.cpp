#include <QApplication>
#include <unistd.h>
#include "core/AppController.h"
#include "core/MetaTypes.h"
#include "gui/MainWindow.h"
#include "core/Logger.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    registerMetaTypes();

    Logger::instance().enableFileOutput("netguardian_debug.log");
    Logger::instance().setLevel(LogLevel::DEBUG);

    if (getuid() != 0) {
        Logger::instance().log(LogLevel::WARN, "APP",
            "running without root, simulation mode will be used if live capture requires privileges");
    }

    AppController app_controller;
    MainWindow mainWindow(&app_controller);

    QString interface;
    if (argc > 1) {
        interface = argv[1];
    } else {
        const auto interfaces = app_controller.getNICModule().listInterfaces();
        if (!interfaces.empty()) {
            interface = QString::fromStdString(interfaces.front());
        }
    }

    mainWindow.show();
    if (!interface.isEmpty()) {
        app_controller.startCapture(interface);
    }

    return app.exec();
}
