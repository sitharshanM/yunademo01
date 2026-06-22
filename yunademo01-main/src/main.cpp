#include "Common.h"
#include "Logger.h"
#include "FirewallManager.h"
#include "mainwindow.h"
#include <QtWidgets/QApplication>
#include <csignal>
#include <iostream>

void signalHandler(int signum) {
    std::cout << "Interrupt signal (" << signum
              << ") received. Shutting down gracefully..." << std::endl;
    running = false;
}

void displayBanner() {
    std::cout << R"(
    ██╗ ██╗██╗ ██╗███╗ ██╗ █████╗
    ╚██╗ ██╔╝██║ ██║████╗ ██║██╔══██╗
     ╚████╔╝ ██║ ██║██╔██╗ ██║███████║
      ╚██╔╝ ██║ ██║██║╚██╗██║██╔══██║
       ██║ ╚██████╔╝██║ ╚████║██║ ██║
       ╚═╝ ╚═════╝ ╚═╝ ╚═══╝╚═╝ ╚═╝
        Firewall Management System
    )" << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signalHandler);
    displayBanner();
    Logger::setLevel(Logger::DEBUG);
    Logger::startAsyncLogger();
    Logger::rotateLogs();

    std::string interface = (argc > 1) ? argv[1] : "eth0";
    FirewallManager manager(interface);
    int exitCode = 0;

    if (argc > 2 && std::string(argv[2]) == "gui") {
        QApplication app(argc, argv);
        GUIMainWindow window(&manager);
        window.show();
        exitCode = app.exec();
    } else {
        manager.runCLI();
    }

    Logger::shutdownAsyncLogger();
    return exitCode;
}
