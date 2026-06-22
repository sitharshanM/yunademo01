QT += core gui widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = yunademo01
TEMPLATE = app

SOURCES += yuna1.cpp \
           mainwindow.cpp

HEADERS += mainwindow.h \
           FirewallManager.h

LIBS += -lpcap -lcurl -lreadline

CONFIG += c++17
QMAKE_CXXFLAGS += -std=c++17