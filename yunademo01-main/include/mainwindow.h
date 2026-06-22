#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTextEdit>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QComboBox>
#include <QTableWidget>
#include <QListWidget>
#include <QSpinBox>
#include <QCheckBox>
#include <iostream>

class FirewallManager;

class TextEditStream : public std::basic_streambuf<char> {
private:
    QTextEdit* textEdit;
public:
    TextEditStream(QTextEdit* te) : textEdit(te) {}
protected:
    virtual std::streamsize xsputn(const char *s, std::streamsize n) {
        textEdit->append(QString::fromUtf8(s, static_cast<int>(n)));
        return n;
    }
    virtual int overflow(int c) {
        if (c != EOF) {
            textEdit->append(QString(static_cast<char>(c)));
        }
        return c;
    }
};

class GUIMainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit GUIMainWindow(FirewallManager* mgr, QWidget *parent = nullptr);
    virtual ~GUIMainWindow();

private:
    FirewallManager* manager;
    QTextEdit* statusText;
    TextEditStream* coutStream;
    std::streambuf* oldCoutBuf;
    QTableWidget* packetTable;

    QLineEdit* knockSequenceInput;
    QSpinBox* knockWindowSpin;
    QSpinBox* knockTargetSpin;
    QSpinBox* knockDurationSpin;
    QCheckBox* dnsSinkholeCheck;
    QLineEdit* macAddressInput;
    QLabel* currentMacValLabel;

    // VPN Pool UI
    QTableWidget* vpnTable;
    QLineEdit* vpnNameInput;
    QComboBox* vpnTypeCombo;
    QLineEdit* vpnConfigInput;
    QLabel* activeVpnLabel;

    // Threat Sync UI
    QListWidget* feedListWidget;
    QLineEdit* feedUrlInput;
    QLabel* threatIpCountLabel;
    QSpinBox* syncIntervalSpin;
    QCheckBox* autoSyncCheck;

    // QoS Shaper UI
    QTableWidget* qosTable;
    QLineEdit* qosValueInput;
    QComboBox* qosTypeCombo;
    QComboBox* qosDirCombo;
    QLineEdit* qosRateInput;

    // Device Mapper UI
    QTableWidget* deviceTable;
    QPushButton* scanDevicesBtn;

    // Honeypot UI
    QLabel* honeypotStatusLabel;
    QTableWidget* honeypotTriggerTable;
    QListWidget* trapPortsList;
    QSpinBox* addTrapPortSpin;

    // IPS UI
    QTableWidget* ipsRulesTable;
    QTableWidget* ipsAlertsTable;
    QLineEdit* ipsRuleInput;

    // DPI UI
    QTableWidget* dpiTable;

    // Topology UI
    TopologyWidget* topologyWidget;

    void updateVpnTable();
    void updateFeedList();
    void updateThreatSyncStats();
    void updateQosTable();
    void updateDeviceTable();
    void updateHoneypotTab();
    void updateIpsTable();
    void updateDpiTable();
    void updateTopologyTab();

    QWidget* createBlockTab();
    QWidget* createFirewallTab();
    QWidget* createNetworkTab();
    QWidget* createThreatTab();
    QWidget* createVpnTab();
    QWidget* createLoggingTab();
    QWidget* createStatusTab();
    QWidget* createSchedulerTab();
    QWidget* createSnifferTab();
    QWidget* createAdvancedControlTab();
    QWidget* createQosTab();
    QWidget* createDeviceMapperTab();
    QWidget* createHoneypotTab();
    QWidget* createIpsTab();
    QWidget* createDpiTab();
    QWidget* createTopologyTab();
    void updateSnifferGrid();
};

#endif // MAINWINDOW_H