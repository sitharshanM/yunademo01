QT += core gui widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = yunademo01
TEMPLATE = app

INCLUDEPATH += include

HEADERS += include/Common.h \
           include/Logger.h \
           include/NeuralNetwork.h \
           include/PacketSniffer.h \
           include/ThreatIntelligenceIntegrator.h \
           include/FirewallManager.h \
           include/mainwindow.h \
           include/concurrentqueue.h \
           include/VPNPoolManager.h \
           include/ThreatIntelSynchronizer.h \
           include/QosManager.h \
           include/DeviceMapper.h \
           include/HoneypotManager.h \
           include/IpsEngine.h

SOURCES += src/main.cpp \
           src/Logger.cpp \
           src/NeuralNetwork.cpp \
           src/PacketSniffer.cpp \
           src/ThreatIntelligenceIntegrator.cpp \
           src/FirewallManager.cpp \
           src/mainwindow.cpp \
           src/VPNPoolManager.cpp \
           src/ThreatIntelSynchronizer.cpp \
           src/QosManager.cpp \
           src/DeviceMapper.cpp \
           src/HoneypotManager.cpp \
           src/IpsEngine.cpp

LIBS += -lpcap -lcurl -lreadline

CONFIG += c++17
QMAKE_CXXFLAGS += -std=c++17