#include "mainwindow.h"
#include "FirewallManager.h"
#include "Logger.h"
#include "QosManager.h"
#include "ThreatIntelSynchronizer.h"
#include "VPNPoolManager.h"
#include "DeviceMapper.h"
#include "HoneypotManager.h"
#include "DpiClassifier.h"
#include "TopologyWidget.h"
#include <QAbstractItemView>
#include <QBrush>
#include <QCheckBox>
#include <QColor>
#include <QComboBox>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>
#include <iostream>

using namespace std;

GUIMainWindow::GUIMainWindow(FirewallManager *mgr, QWidget *parent)
    : QMainWindow(parent), manager(mgr) {
  setWindowTitle("YUNA Firewall Manager");
  setMinimumSize(800, 600);

  statusText = new QTextEdit(this);
  statusText->setReadOnly(true);
  coutStream = new TextEditStream(statusText);
  oldCoutBuf = std::cout.rdbuf(coutStream);

  QTabWidget *tabs = new QTabWidget(this);

  tabs->addTab(createBlockTab(), "Block");
  tabs->addTab(createFirewallTab(), "Firewall");
  tabs->addTab(createNetworkTab(), "Network");
  tabs->addTab(createThreatTab(), "Threat");
  tabs->addTab(createVpnTab(), "VPN");
  tabs->addTab(createLoggingTab(), "Logging");
  tabs->addTab(createStatusTab(), "Status");
  tabs->addTab(createSchedulerTab(), "Scheduler");
  tabs->addTab(createSnifferTab(), "Live Sniffer");
  tabs->addTab(createAdvancedControlTab(), "Advanced Control");
  tabs->addTab(createQosTab(), "QoS Shaper");
  tabs->addTab(createDeviceMapperTab(), "Device Mapper");
  tabs->addTab(createHoneypotTab(), "Active Honeypot");
  tabs->addTab(createIpsTab(), "IPS Engine");
  tabs->addTab(createDpiTab(), "DPI Analytics");
  tabs->addTab(createTopologyTab(), "Network Topology");

  QTimer *timer = new QTimer(this);
  connect(timer, &QTimer::timeout, [this]() {
    updateSnifferGrid();
    updateVpnTable();
    updateThreatSyncStats();
    updateQosTable();
    updateDeviceTable();
    updateHoneypotTab();
    updateIpsTable();
    updateDpiTable();
    updateTopologyTab();
  });
  timer->start(1000);

  updateVpnTable();
  updateFeedList();
  updateThreatSyncStats();
  updateQosTable();
  updateDeviceTable();
  updateHoneypotTab();
  updateIpsTable();
  updateDpiTable();
  updateTopologyTab();

  QVBoxLayout *mainLayout = new QVBoxLayout;
  mainLayout->addWidget(tabs);
  mainLayout->addWidget(new QLabel("Status Output:"));
  mainLayout->addWidget(statusText);

  QWidget *central = new QWidget;
  central->setLayout(mainLayout);
  setCentralWidget(central);
}

GUIMainWindow::~GUIMainWindow() {
  std::cout.rdbuf(oldCoutBuf);
  delete coutStream;
}

QWidget *GUIMainWindow::createBlockTab() {
  QWidget *tab = new QWidget;
  QGridLayout *layout = new QGridLayout;
  int row = 0;

  // Block/Unblock IP
  QLabel *ipLabel = new QLabel("IP Address:");
  QLineEdit *ipInput = new QLineEdit;
  QPushButton *blockIpBtn = new QPushButton("Block IP");
  connect(blockIpBtn, &QPushButton::clicked, [this, ipInput]() {
    string ip = ipInput->text().toStdString();
    if (!ip.empty()) {
      manager->blockIPAddress(ip);
    } else {
      statusText->append("Error: Enter an IP address.");
    }
  });
  QPushButton *unblockIpBtn = new QPushButton("Unblock IP");
  connect(unblockIpBtn, &QPushButton::clicked, [this, ipInput]() {
    string ip = ipInput->text().toStdString();
    if (!ip.empty()) {
      manager->unblockIPAddress(ip);
    } else {
      statusText->append("Error: Enter an IP address.");
    }
  });
  layout->addWidget(ipLabel, row, 0);
  layout->addWidget(ipInput, row, 1);
  layout->addWidget(blockIpBtn, row, 2);
  layout->addWidget(unblockIpBtn, row, 3);
  row++;

  // Block Website
  QLabel *websiteLabel = new QLabel("Website Domain:");
  QLineEdit *websiteInput = new QLineEdit;
  QPushButton *blockWebsiteBtn = new QPushButton("Block Website");
  connect(blockWebsiteBtn, &QPushButton::clicked, [this, websiteInput]() {
    string site = websiteInput->text().toStdString();
    if (!site.empty()) {
      manager->blockWebsite(site);
    } else {
      statusText->append("Error: Enter a website domain.");
    }
  });
  layout->addWidget(websiteLabel, row, 0);
  layout->addWidget(websiteInput, row, 1);
  layout->addWidget(blockWebsiteBtn, row, 2);
  row++;

  // Block/Unblock Domain
  QLabel *domainLabel = new QLabel("Domain:");
  QLineEdit *domainInput = new QLineEdit;
  QLabel *catLabel = new QLabel("Category (optional):");
  QLineEdit *catInput = new QLineEdit;
  QPushButton *blockDomainBtn = new QPushButton("Block Domain");
  connect(blockDomainBtn, &QPushButton::clicked,
          [this, domainInput, catInput]() {
            string domain = domainInput->text().toStdString();
            string cat = catInput->text().toStdString();
            if (!domain.empty()) {
              manager->blockDomain(domain, cat);
            } else {
              statusText->append("Error: Enter a domain.");
            }
          });
  QPushButton *unblockDomainBtn = new QPushButton("Unblock Domain");
  connect(unblockDomainBtn, &QPushButton::clicked, [this, domainInput]() {
    string domain = domainInput->text().toStdString();
    if (!domain.empty()) {
      manager->unblockDomain(domain);
    } else {
      statusText->append("Error: Enter a domain.");
    }
  });
  layout->addWidget(domainLabel, row, 0);
  layout->addWidget(domainInput, row, 1);
  layout->addWidget(blockDomainBtn, row, 2);
  layout->addWidget(unblockDomainBtn, row, 3);
  row++;
  layout->addWidget(catLabel, row, 0);
  layout->addWidget(catInput, row, 1);
  row++;

  // Block/Unblock Category
  QLabel *categoryLabel = new QLabel("Category:");
  QComboBox *categoryCombo = new QComboBox;
  categoryCombo->addItems({"sports", "news", "technology", "entertainment",
                           "finance", "health", "travel", "education",
                           "lifestyle", "science", "gaming", "food",
                           "fashion"});
  QPushButton *blockCatBtn = new QPushButton("Block Category");
  connect(blockCatBtn, &QPushButton::clicked, [this, categoryCombo]() {
    string cat = categoryCombo->currentText().toStdString();
    manager->blockCategory(cat);
  });
  QPushButton *unblockCatBtn = new QPushButton("Unblock Category");
  connect(unblockCatBtn, &QPushButton::clicked, [this, categoryCombo]() {
    string cat = categoryCombo->currentText().toStdString();
    manager->unblockCategory(cat);
  });
  layout->addWidget(categoryLabel, row, 0);
  layout->addWidget(categoryCombo, row, 1);
  layout->addWidget(blockCatBtn, row, 2);
  layout->addWidget(unblockCatBtn, row, 3);
  row++;

  // Block/Unblock All Traffic
  QPushButton *blockAllBtn = new QPushButton("Block All Traffic");
  connect(blockAllBtn, &QPushButton::clicked,
          [this]() { manager->blockAllTraffic(); });
  QPushButton *unblockAllBtn = new QPushButton("Unblock All Traffic");
  connect(unblockAllBtn, &QPushButton::clicked,
          [this]() { manager->unblockAllTraffic(); });
  layout->addWidget(blockAllBtn, row, 0, 1, 2);
  layout->addWidget(unblockAllBtn, row, 2, 1, 2);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createFirewallTab() {
  QWidget *tab = new QWidget;
  QGridLayout *layout = new QGridLayout;
  int row = 0;

  // Add/Remove Port
  QLabel *portLabel = new QLabel("Port:");
  QLineEdit *portInput = new QLineEdit;
  QLabel *protoLabel = new QLabel("Protocol:");
  QComboBox *protoCombo = new QComboBox;
  protoCombo->addItems({"tcp", "udp"});
  QPushButton *addPortBtn = new QPushButton("Add Port");
  connect(addPortBtn, &QPushButton::clicked, [this, portInput, protoCombo]() {
    string port = portInput->text().toStdString();
    string proto = protoCombo->currentText().toStdString();
    if (!port.empty()) {
      manager->addFirewallRule("accept", "in", "0.0.0.0/0", port, proto);
    } else {
      statusText->append("Error: Enter a port.");
    }
  });
  QPushButton *removePortBtn = new QPushButton("Remove Port");
  connect(
      removePortBtn, &QPushButton::clicked, [this, portInput, protoCombo]() {
        string port = portInput->text().toStdString();
        string proto = protoCombo->currentText().toStdString();
        if (!port.empty()) {
          manager->removeFirewallRule("accept", "in", "0.0.0.0/0", port, proto);
        } else {
          statusText->append("Error: Enter a port.");
        }
      });
  layout->addWidget(portLabel, row, 0);
  layout->addWidget(portInput, row, 1);
  layout->addWidget(protoLabel, row, 2);
  layout->addWidget(protoCombo, row, 3);
  row++;
  layout->addWidget(addPortBtn, row, 0, 1, 2);
  layout->addWidget(removePortBtn, row, 2, 1, 2);
  row++;

  // Add NAT
  QLabel *srcIpLabel = new QLabel("Source IP:");
  QLineEdit *srcIpInput = new QLineEdit;
  QLabel *destIpLabel = new QLabel("Destination IP:");
  QLineEdit *destIpInput = new QLineEdit;
  QLabel *natPortLabel = new QLabel("Port:");
  QLineEdit *natPortInput = new QLineEdit;
  QPushButton *addNatBtn = new QPushButton("Add NAT Rule");
  connect(addNatBtn, &QPushButton::clicked,
          [this, srcIpInput, destIpInput, natPortInput]() {
            string src = srcIpInput->text().toStdString();
            string dest = destIpInput->text().toStdString();
            string port = natPortInput->text().toStdString();
            if (!src.empty() && !dest.empty() && !port.empty()) {
              manager->addNatRule(src, dest, port);
            } else {
              statusText->append("Error: Fill all fields for NAT.");
            }
          });
  layout->addWidget(srcIpLabel, row, 0);
  layout->addWidget(srcIpInput, row, 1);
  row++;
  layout->addWidget(destIpLabel, row, 0);
  layout->addWidget(destIpInput, row, 1);
  row++;
  layout->addWidget(natPortLabel, row, 0);
  layout->addWidget(natPortInput, row, 1);
  layout->addWidget(addNatBtn, row, 2);
  row++;

  // Remove NAT
  QLabel *ruleIdLabel = new QLabel("Rule ID:");
  QLineEdit *ruleIdInput = new QLineEdit;
  QPushButton *removeNatBtn = new QPushButton("Remove NAT Rule");
  connect(removeNatBtn, &QPushButton::clicked, [this, ruleIdInput]() {
    string ruleId = ruleIdInput->text().toStdString();
    if (!ruleId.empty()) {
      manager->removeNatRule(ruleId);
    } else {
      statusText->append("Error: Enter rule ID.");
    }
  });
  layout->addWidget(ruleIdLabel, row, 0);
  layout->addWidget(ruleIdInput, row, 1);
  layout->addWidget(removeNatBtn, row, 2);
  row++;

  // Other buttons
  QPushButton *optimizeBtn = new QPushButton("Optimize Rules");
  connect(optimizeBtn, &QPushButton::clicked,
          [this]() { manager->optimizeFirewallRules(); });
  QPushButton *rollbackBtn = new QPushButton("Rollback Rules");
  connect(rollbackBtn, &QPushButton::clicked,
          [this]() { manager->rollbackRules(); });
  QPushButton *restoreBtn = new QPushButton("Restore Default");
  connect(restoreBtn, &QPushButton::clicked,
          [this]() { manager->restoreDefaultConfig(); });
  layout->addWidget(optimizeBtn, row, 0);
  layout->addWidget(rollbackBtn, row, 1);
  layout->addWidget(restoreBtn, row, 2);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createNetworkTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QPushButton *checkInternetBtn =
      new QPushButton("Check Internet Connectivity");
  connect(checkInternetBtn, &QPushButton::clicked,
          [this]() { manager->checkInternetConnectivity(); });
  layout->addWidget(checkInternetBtn);

  QPushButton *checkHealthBtn = new QPushButton("Check Firewall Health");
  connect(checkHealthBtn, &QPushButton::clicked,
          [this]() { manager->checkFirewallHealth(); });
  layout->addWidget(checkHealthBtn);

  QHBoxLayout *geoIpLayout = new QHBoxLayout;
  QLabel *geoIpLabel = new QLabel("IP for GeoIP:");
  QLineEdit *geoIpInput = new QLineEdit;
  QPushButton *geoIpBtn = new QPushButton("Get GeoIP");
  connect(geoIpBtn, &QPushButton::clicked, [this, geoIpInput]() {
    string ip = geoIpInput->text().toStdString();
    if (!ip.empty()) {
      manager->getGeoIP(ip);
    } else {
      statusText->append("Error: Enter an IP.");
    }
  });
  geoIpLayout->addWidget(geoIpLabel);
  geoIpLayout->addWidget(geoIpInput);
  geoIpLayout->addWidget(geoIpBtn);
  layout->addLayout(geoIpLayout);

  QPushButton *cleanupBtn = new QPushButton("Cleanup Expired Connections");
  connect(cleanupBtn, &QPushButton::clicked,
          [this]() { manager->cleanupExpiredConnections(); });
  layout->addWidget(cleanupBtn);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createThreatTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QPushButton *detectThreatBtn = new QPushButton("Detect Threat");
  connect(detectThreatBtn, &QPushButton::clicked, [this]() {
    bool threat = manager->detectThreat();
    statusText->append("Threat detected: " + QString(threat ? "Yes" : "No"));
  });
  layout->addWidget(detectThreatBtn);

  QHBoxLayout *respondLayout = new QHBoxLayout;
  QLabel *respondIpLabel = new QLabel("IP to Respond:");
  QLineEdit *respondIpInput = new QLineEdit;
  QPushButton *respondThreatBtn = new QPushButton("Respond to Threat");
  connect(respondThreatBtn, &QPushButton::clicked, [this, respondIpInput]() {
    string ip = respondIpInput->text().toStdString();
    if (!ip.empty()) {
      manager->respondToThreat(ip);
    } else {
      statusText->append("Error: Enter an IP.");
    }
  });
  respondLayout->addWidget(respondIpLabel);
  respondLayout->addWidget(respondIpInput);
  respondLayout->addWidget(respondThreatBtn);
  layout->addLayout(respondLayout);

  QPushButton *trainBtn = new QPushButton("Train Neural Network");
  connect(trainBtn, &QPushButton::clicked,
          [this]() { manager->trainNeuralNetwork(); });
  layout->addWidget(trainBtn);

  QPushButton *autoHealBtn = new QPushButton("Auto Heal");
  connect(autoHealBtn, &QPushButton::clicked,
          [this]() { manager->autoHeal(); });
  layout->addWidget(autoHealBtn);

  // Threat intelligence synchronization section
  QLabel *syncSectionTitle =
      new QLabel("<b>Threat Intelligence Feed Auto-Synchronizer</b>");
  syncSectionTitle->setStyleSheet("margin-top: 20px; font-size: 13px;");
  layout->addWidget(syncSectionTitle);

  threatIpCountLabel = new QLabel("Cached Threat IPs: <b>0</b>");
  layout->addWidget(threatIpCountLabel);

  feedListWidget = new QListWidget;
  layout->addWidget(feedListWidget);

  QHBoxLayout *feedFormLayout = new QHBoxLayout;
  feedUrlInput = new QLineEdit;
  feedUrlInput->setPlaceholderText(
      "https://raw.githubusercontent.com/... Compromised IPs feed");
  QPushButton *addFeedBtn = new QPushButton("Add Feed URL");
  connect(addFeedBtn, &QPushButton::clicked, [this]() {
    std::string url = feedUrlInput->text().toStdString();
    if (!url.empty()) {
      bool ok = manager->getThreatSync()->addFeedUrl(url);
      if (ok) {
        statusText->append("Added threat intelligence feed URL.");
        feedUrlInput->clear();
        updateFeedList();
      } else {
        statusText->append("Error: URL already exists or is invalid.");
      }
    }
  });

  QPushButton *removeFeedBtn = new QPushButton("Remove Selected");
  connect(removeFeedBtn, &QPushButton::clicked, [this]() {
    QListWidgetItem *current = feedListWidget->currentItem();
    if (current) {
      std::string url = current->text().toStdString();
      manager->getThreatSync()->removeFeedUrl(url);
      statusText->append("Removed feed URL.");
      updateFeedList();
    } else {
      statusText->append("Error: Select a feed URL from the list first.");
    }
  });

  feedFormLayout->addWidget(feedUrlInput);
  feedFormLayout->addWidget(addFeedBtn);
  feedFormLayout->addWidget(removeFeedBtn);
  layout->addLayout(feedFormLayout);

  QHBoxLayout *syncActionLayout = new QHBoxLayout;
  QPushButton *syncNowBtn = new QPushButton("Sync Feeds Now");
  connect(syncNowBtn, &QPushButton::clicked, [this]() {
    statusText->append(
        "Triggering threat feeds download and parse in background thread...");
    std::thread([this]() {
      manager->getThreatSync()->syncNow();
      QMetaObject::invokeMethod(this, [this]() {
        updateThreatSyncStats();
        statusText->append("Threat intelligence synchronization completed.");
      });
    }).detach();
  });

  syncActionLayout->addWidget(syncNowBtn);
  layout->addLayout(syncActionLayout);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createVpnTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  activeVpnLabel = new QLabel("Active VPN: <b>None (Disconnected)</b>");
  activeVpnLabel->setStyleSheet("font-size: 14px; margin-bottom: 10px;");
  layout->addWidget(activeVpnLabel);

  vpnTable = new QTableWidget;
  vpnTable->setColumnCount(4);
  QStringList headers;
  headers << "Name" << "Type" << "Config Path" << "Status";
  vpnTable->setHorizontalHeaderLabels(headers);
  vpnTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  vpnTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  vpnTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  vpnTable->setSelectionMode(QAbstractItemView::SingleSelection);
  layout->addWidget(vpnTable);

  // Profile Control buttons
  QHBoxLayout *btnLayout = new QHBoxLayout;
  QPushButton *connectBtn = new QPushButton("Connect Selected");
  connect(connectBtn, &QPushButton::clicked, [this]() {
    int row = vpnTable->currentRow();
    if (row >= 0) {
      std::string name = vpnTable->item(row, 0)->text().toStdString();
      manager->getVpnPool()->connectProfile(name);
      updateVpnTable();
    } else {
      statusText->append("Error: Select a profile from the table first.");
    }
  });

  QPushButton *disconnectBtn = new QPushButton("Disconnect Active");
  connect(disconnectBtn, &QPushButton::clicked, [this]() {
    manager->getVpnPool()->disconnectActive();
    updateVpnTable();
  });

  QPushButton *removeBtn = new QPushButton("Remove Selected");
  connect(removeBtn, &QPushButton::clicked, [this]() {
    int row = vpnTable->currentRow();
    if (row >= 0) {
      std::string name = vpnTable->item(row, 0)->text().toStdString();
      bool ok = manager->getVpnPool()->removeProfile(name);
      if (ok) {
        statusText->append(
            QString("Removed profile: %1").arg(QString::fromStdString(name)));
        updateVpnTable();
      } else {
        statusText->append("Error: Could not remove selected profile.");
      }
    } else {
      statusText->append("Error: Select a profile from the table first.");
    }
  });

  QPushButton *failoverBtn = new QPushButton("Trigger Failover");
  connect(failoverBtn, &QPushButton::clicked, [this]() {
    statusText->append("Triggering VPN failover...");
    bool ok = manager->getVpnPool()->performFailover();
    if (ok) {
      statusText->append("Failover switch completed.");
    } else {
      statusText->append("Failover switch failed or no other targets exist.");
    }
    updateVpnTable();
  });

  btnLayout->addWidget(connectBtn);
  btnLayout->addWidget(disconnectBtn);
  btnLayout->addWidget(removeBtn);
  btnLayout->addWidget(failoverBtn);
  layout->addLayout(btnLayout);

  // Add Profile Form
  QLabel *formTitle = new QLabel("<b>Add VPN Profile:</b>");
  formTitle->setStyleSheet("margin-top: 15px;");
  layout->addWidget(formTitle);

  QGridLayout *formLayout = new QGridLayout;

  QLabel *nameLabel = new QLabel("Profile Name:");
  vpnNameInput = new QLineEdit;
  vpnNameInput->setPlaceholderText("e.g. wg-server-01");

  QLabel *typeLabel = new QLabel("VPN Type:");
  vpnTypeCombo = new QComboBox;
  vpnTypeCombo->addItems({"wireguard", "openvpn"});

  QLabel *pathLabel = new QLabel("Config File:");
  vpnConfigInput = new QLineEdit;
  QPushButton *browseBtn = new QPushButton("Browse");
  connect(browseBtn, &QPushButton::clicked, [this]() {
    QString file = QFileDialog::getOpenFileName(
        nullptr, "Select VPN Config", "",
        "WireGuard/OpenVPN Configs (*.conf *.ovpn);;All Files (*)");
    if (!file.isEmpty()) {
      vpnConfigInput->setText(file);
    }
  });

  QPushButton *addBtn = new QPushButton("Add Profile to Pool");
  connect(addBtn, &QPushButton::clicked, [this]() {
    std::string name = vpnNameInput->text().toStdString();
    std::string type = vpnTypeCombo->currentText().toStdString();
    std::string path = vpnConfigInput->text().toStdString();

    if (name.empty() || path.empty()) {
      statusText->append("Error: Fill all profile form fields.");
      return;
    }

    bool ok = manager->getVpnPool()->addProfile(name, type, path);
    if (ok) {
      statusText->append(
          QString("Added profile: %1").arg(QString::fromStdString(name)));
      vpnNameInput->clear();
      vpnConfigInput->clear();
      updateVpnTable();
    } else {
      statusText->append("Failed to add profile. Ensure it does not already "
                         "exist and file path is valid.");
    }
  });

  formLayout->addWidget(nameLabel, 0, 0);
  formLayout->addWidget(vpnNameInput, 0, 1, 1, 2);
  formLayout->addWidget(typeLabel, 1, 0);
  formLayout->addWidget(vpnTypeCombo, 1, 1, 1, 2);
  formLayout->addWidget(pathLabel, 2, 0);
  formLayout->addWidget(vpnConfigInput, 2, 1);
  formLayout->addWidget(browseBtn, 2, 2);
  formLayout->addWidget(addBtn, 3, 0, 1, 3);
  layout->addLayout(formLayout);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createLoggingTab() {
  QWidget *tab = new QWidget;
  QGridLayout *layout = new QGridLayout;
  int row = 0;

  // Send Notification
  QLabel *titleLabel = new QLabel("Title:");
  QLineEdit *titleInput = new QLineEdit;
  QLabel *msgLabel = new QLabel("Message:");
  QLineEdit *msgInput = new QLineEdit;
  QPushButton *sendNotifBtn = new QPushButton("Send Notification");
  connect(sendNotifBtn, &QPushButton::clicked, [this, titleInput, msgInput]() {
    string title = titleInput->text().toStdString();
    string msg = msgInput->text().toStdString();
    if (!title.empty() && !msg.empty()) {
      manager->sendNotification(title, msg);
    } else {
      statusText->append("Error: Fill title and message.");
    }
  });
  layout->addWidget(titleLabel, row, 0);
  layout->addWidget(titleInput, row, 1);
  row++;
  layout->addWidget(msgLabel, row, 0);
  layout->addWidget(msgInput, row, 1);
  layout->addWidget(sendNotifBtn, row, 2);
  row++;

  // Rule Violation
  QLabel *ruleLabel = new QLabel("Rule:");
  QLineEdit *ruleInput = new QLineEdit;
  QLabel *detailLabel = new QLabel("Detail:");
  QLineEdit *detailInput = new QLineEdit;
  QPushButton *violationBtn = new QPushButton("Report Violation");
  connect(violationBtn, &QPushButton::clicked,
          [this, ruleInput, detailInput]() {
            string rule = ruleInput->text().toStdString();
            string detail = detailInput->text().toStdString();
            if (!rule.empty() && !detail.empty()) {
              manager->ruleViolationDetected(rule, detail);
            } else {
              statusText->append("Error: Fill rule and detail.");
            }
          });
  layout->addWidget(ruleLabel, row, 0);
  layout->addWidget(ruleInput, row, 1);
  row++;
  layout->addWidget(detailLabel, row, 0);
  layout->addWidget(detailInput, row, 1);
  layout->addWidget(violationBtn, row, 2);
  row++;

  // Set Log Level
  QLabel *logLevelLabel = new QLabel("Log Level:");
  QComboBox *logLevelCombo = new QComboBox;
  logLevelCombo->addItems({"INFO", "WARNING", "ERROR", "DEBUG"});
  QPushButton *setLogLevelBtn = new QPushButton("Set Log Level");
  connect(setLogLevelBtn, &QPushButton::clicked, [logLevelCombo]() {
    string level = logLevelCombo->currentText().toStdString();
    if (level == "INFO")
      Logger::setLevel(Logger::INFO);
    else if (level == "WARNING")
      Logger::setLevel(Logger::WARNING);
    else if (level == "ERROR")
      Logger::setLevel(Logger::ERROR);
    else if (level == "DEBUG")
      Logger::setLevel(Logger::DEBUG);
  });
  layout->addWidget(logLevelLabel, row, 0);
  layout->addWidget(logLevelCombo, row, 1);
  layout->addWidget(setLogLevelBtn, row, 2);
  row++;

  // Rotate Logs
  QPushButton *rotateLogsBtn = new QPushButton("Rotate Logs");
  connect(rotateLogsBtn, &QPushButton::clicked, []() { Logger::rotateLogs(); });
  layout->addWidget(rotateLogsBtn, row, 0);

  // Log Message
  QLabel *customLevelLabel = new QLabel("Level:");
  QComboBox *customLevelCombo = new QComboBox;
  customLevelCombo->addItems({"INFO", "WARNING", "ERROR", "DEBUG"});
  QLabel *customMsgLabel = new QLabel("Message:");
  QLineEdit *customMsgInput = new QLineEdit;
  QPushButton *logMsgBtn = new QPushButton("Log Message");
  connect(logMsgBtn, &QPushButton::clicked,
          [customLevelCombo, customMsgInput]() {
            string level = customLevelCombo->currentText().toStdString();
            string msg = customMsgInput->text().toStdString();
            if (!msg.empty()) {
              if (level == "INFO")
                Logger::log(msg, Logger::INFO);
              else if (level == "WARNING")
                Logger::log(msg, Logger::WARNING);
              else if (level == "ERROR")
                Logger::log(msg, Logger::ERROR);
              else if (level == "DEBUG")
                Logger::log(msg, Logger::DEBUG);
            }
          });
  layout->addWidget(customLevelLabel, row, 1);
  layout->addWidget(customLevelCombo, row, 2);
  row++;
  layout->addWidget(customMsgLabel, row, 0);
  layout->addWidget(customMsgInput, row, 1);
  layout->addWidget(logMsgBtn, row, 2);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createStatusTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QPushButton *showStatusBtn = new QPushButton("Show Status");
  connect(showStatusBtn, &QPushButton::clicked, [this]() {
    string status = manager->getStatus();
    statusText->append(QString::fromStdString(status));
  });
  layout->addWidget(showStatusBtn);

  QHBoxLayout *exportLayout = new QHBoxLayout;
  QLabel *exportLabel = new QLabel("Export Filename:");
  QLineEdit *exportInput = new QLineEdit;
  QPushButton *exportBtn = new QPushButton("Export Blocked IPs");
  connect(exportBtn, &QPushButton::clicked, [this, exportInput]() {
    string filename = exportInput->text().toStdString();
    if (!filename.empty()) {
      manager->exportBlockedIPsToCSV(filename);
    } else {
      statusText->append("Error: Enter filename.");
    }
  });
  exportLayout->addWidget(exportLabel);
  exportLayout->addWidget(exportInput);
  exportLayout->addWidget(exportBtn);
  layout->addLayout(exportLayout);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createSchedulerTab() {
  QWidget *tab = new QWidget;
  QGridLayout *layout = new QGridLayout;
  int row = 0;

  // Category Schedule inputs
  QLabel *catLabel = new QLabel("Category:");
  QComboBox *catCombo = new QComboBox;
  catCombo->addItems({"sports", "news", "technology", "entertainment",
                      "finance", "health", "travel", "education", "lifestyle",
                      "science", "gaming", "food", "fashion"});

  QLabel *startLabel = new QLabel("Start Hour (0-23):");
  QSpinBox *startSpin = new QSpinBox;
  startSpin->setRange(0, 23);

  QLabel *endLabel = new QLabel("End Hour (0-23):");
  QSpinBox *endSpin = new QSpinBox;
  endSpin->setRange(0, 23);

  QCheckBox *enableCheck = new QCheckBox("Enable Schedule");

  QPushButton *saveBtn = new QPushButton("Save Schedule");
  connect(saveBtn, &QPushButton::clicked,
          [this, catCombo, startSpin, endSpin, enableCheck]() {
            string cat = catCombo->currentText().toStdString();
            int start = startSpin->value();
            int end = endSpin->value();
            bool enabled = enableCheck->isChecked();
            manager->setCategorySchedule(cat, start, end, enabled);
            statusText->append(QString::fromStdString(
                "Saved schedule for " + cat + ": " + to_string(start) + " to " +
                to_string(end) + " (Enabled: " + (enabled ? "Yes" : "No") +
                ")"));
          });

  layout->addWidget(catLabel, row, 0);
  layout->addWidget(catCombo, row, 1);
  row++;
  layout->addWidget(startLabel, row, 0);
  layout->addWidget(startSpin, row, 1);
  row++;
  layout->addWidget(endLabel, row, 0);
  layout->addWidget(endSpin, row, 1);
  row++;
  layout->addWidget(enableCheck, row, 0, 1, 2);
  row++;
  layout->addWidget(saveBtn, row, 0, 1, 2);
  row++;

  // Discord/Slack Webhook URL
  QLabel *webhookLabel = new QLabel("Webhook URL:");
  QLineEdit *webhookInput = new QLineEdit;
  webhookInput->setText(QString::fromStdString(manager->getWebhookUrl()));

  QPushButton *saveWebhookBtn = new QPushButton("Save Webhook");
  connect(saveWebhookBtn, &QPushButton::clicked, [this, webhookInput]() {
    string url = webhookInput->text().toStdString();
    manager->setWebhookUrl(url);
    statusText->append("Webhook URL saved.");
  });

  QPushButton *testWebhookBtn = new QPushButton("Send Test Alert");
  connect(testWebhookBtn, &QPushButton::clicked, [this]() {
    manager->sendNotification(
        "Test Notification", "This is a test notification from YUNA Firewall!");
  });

  row++;
  layout->addWidget(new QLabel("Alert Notifications Configuration:"), row, 0, 1,
                    2);
  row++;
  layout->addWidget(webhookLabel, row, 0);
  layout->addWidget(webhookInput, row, 1);
  row++;
  layout->addWidget(saveWebhookBtn, row, 0);
  layout->addWidget(testWebhookBtn, row, 1);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createSnifferTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  packetTable = new QTableWidget(this);
  packetTable->setColumnCount(8);
  QStringList headers;
  headers << "Timestamp" << "Protocol" << "Src IP" << "Src Port" << "Dest IP"
          << "Dest Port" << "Size" << "Status";
  packetTable->setHorizontalHeaderLabels(headers);
  packetTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);

  QPushButton *clearBtn = new QPushButton("Clear Log");
  connect(clearBtn, &QPushButton::clicked, [this]() {
    packetTable->setRowCount(0);
    manager->clearRecentPackets();
  });

  layout->addWidget(packetTable);
  layout->addWidget(clearBtn);
  tab->setLayout(layout);
  return tab;
}

void GUIMainWindow::updateSnifferGrid() {
  std::vector<LivePacketRecord> packets = manager->getRecentPackets();
  packetTable->setRowCount(0);
  packetTable->setRowCount(static_cast<int>(packets.size()));

  for (int i = 0; i < static_cast<int>(packets.size()); ++i) {
    const auto &pkt = packets[i];

    QTableWidgetItem *timeItem =
        new QTableWidgetItem(QString::fromStdString(pkt.timestamp));
    QTableWidgetItem *protoItem =
        new QTableWidgetItem(QString::fromStdString(pkt.protocol));
    QTableWidgetItem *srcIpItem =
        new QTableWidgetItem(QString::fromStdString(pkt.sourceIP));
    QTableWidgetItem *srcPortItem =
        new QTableWidgetItem(QString::fromStdString(pkt.sourcePort));
    QTableWidgetItem *dstIpItem =
        new QTableWidgetItem(QString::fromStdString(pkt.destIP));
    QTableWidgetItem *dstPortItem =
        new QTableWidgetItem(QString::fromStdString(pkt.destPort));
    QTableWidgetItem *sizeItem =
        new QTableWidgetItem(QString::number(pkt.size));
    QTableWidgetItem *statusItem =
        new QTableWidgetItem(QString::fromStdString(pkt.status));

    // Color coding for status
    if (pkt.status == "Blocked") {
      statusItem->setBackground(QBrush(QColor(255, 230, 230)));
      statusItem->setForeground(QBrush(QColor(200, 0, 0)));
    } else if (pkt.status == "Flagged") {
      statusItem->setBackground(QBrush(QColor(255, 245, 220)));
      statusItem->setForeground(QBrush(QColor(200, 100, 0)));
    } else { // "Allowed"
      statusItem->setBackground(QBrush(QColor(230, 255, 230)));
      statusItem->setForeground(QBrush(QColor(0, 150, 0)));
    }

    statusItem->setTextAlignment(Qt::AlignCenter);

    packetTable->setItem(i, 0, timeItem);
    packetTable->setItem(i, 1, protoItem);
    packetTable->setItem(i, 2, srcIpItem);
    packetTable->setItem(i, 3, srcPortItem);
    packetTable->setItem(i, 4, dstIpItem);
    packetTable->setItem(i, 5, dstPortItem);
    packetTable->setItem(i, 6, sizeItem);
    packetTable->setItem(i, 7, statusItem);
  }
}

QWidget *GUIMainWindow::createAdvancedControlTab() {
  QWidget *tab = new QWidget;
  QGridLayout *layout = new QGridLayout;
  int row = 0;

  // --- Port Knocking Configuration ---
  QLabel *seqLabel = new QLabel("Knock Sequence (comma-separated ports):");
  knockSequenceInput = new QLineEdit;
  std::vector<int> seq = manager->getKnockSequence();
  QStringList seqStrList;
  for (int port : seq) {
    seqStrList << QString::number(port);
  }
  knockSequenceInput->setText(seqStrList.join(", "));

  QLabel *windowLabel = new QLabel("Knock Timeout Window (seconds):");
  knockWindowSpin = new QSpinBox;
  knockWindowSpin->setRange(1, 300);
  knockWindowSpin->setValue(manager->getKnockWindow());

  QLabel *targetLabel = new QLabel("Knock Target Port to Open:");
  knockTargetSpin = new QSpinBox;
  knockTargetSpin->setRange(1, 65535);
  knockTargetSpin->setValue(manager->getKnockTargetPort());

  QLabel *durationLabel = new QLabel("Target Port Open Duration (seconds):");
  knockDurationSpin = new QSpinBox;
  knockDurationSpin->setRange(5, 3600);
  knockDurationSpin->setValue(manager->getKnockDuration());

  QPushButton *saveKnockBtn = new QPushButton("Save Port Knock Settings");
  connect(saveKnockBtn, &QPushButton::clicked, [this]() {
    QStringList parts = knockSequenceInput->text().split(',');
    std::vector<int> newSeq;
    for (const QString &part : parts) {
      QString trimmed = part.trimmed();
      if (!trimmed.isEmpty()) {
        bool ok;
        int port = trimmed.toInt(&ok);
        if (ok && port >= 1 && port <= 65535) {
          newSeq.push_back(port);
        }
      }
    }
    if (newSeq.empty()) {
      statusText->append(
          "Error: Knock sequence must contain at least one valid port.");
      return;
    }
    int window = knockWindowSpin->value();
    int target = knockTargetSpin->value();
    int duration = knockDurationSpin->value();

    manager->setKnockConfig(newSeq, window, target, duration);
    statusText->append("Port knocking configuration updated and saved.");
  });

  layout->addWidget(new QLabel("<b>Dynamic Port Knocking Configuration:</b>"),
                    row, 0, 1, 2);
  row++;
  layout->addWidget(seqLabel, row, 0);
  layout->addWidget(knockSequenceInput, row, 1);
  row++;
  layout->addWidget(windowLabel, row, 0);
  layout->addWidget(knockWindowSpin, row, 1);
  row++;
  layout->addWidget(targetLabel, row, 0);
  layout->addWidget(knockTargetSpin, row, 1);
  row++;
  layout->addWidget(durationLabel, row, 0);
  layout->addWidget(knockDurationSpin, row, 1);
  row++;
  layout->addWidget(saveKnockBtn, row, 0, 1, 2);
  row++;

  // Spacer
  layout->addWidget(new QLabel(""), row, 0, 1, 2);
  row++;

  // --- DNS Sinkhole Configuration ---
  layout->addWidget(
      new QLabel("<b>DNS Sinkholing (Pi-hole style) Configuration:</b>"), row,
      0, 1, 2);
  row++;

  dnsSinkholeCheck = new QCheckBox("Enable DNS Sinkholing");
  dnsSinkholeCheck->setChecked(manager->isDnsSinkholeEnabled());

  QPushButton *saveDnsBtn = new QPushButton("Save DNS Settings");
  connect(saveDnsBtn, &QPushButton::clicked, [this]() {
    bool enabled = dnsSinkholeCheck->isChecked();
    manager->setDnsSinkholeEnabled(enabled);
    statusText->append(QString("DNS Sinkholing ") +
                       (enabled ? "Enabled." : "Disabled."));
  });

  layout->addWidget(dnsSinkholeCheck, row, 0, 1, 2);
  row++;
  layout->addWidget(saveDnsBtn, row, 0, 1, 2);
  row++;

  // Spacer
  layout->addWidget(new QLabel(""), row, 0, 1, 2);
  row++;

  // --- MAC Anonymizer Configuration ---
  layout->addWidget(new QLabel("<b>Interface MAC Address Anonymizer:</b>"), row,
                    0, 1, 2);
  row++;

  QLabel *ifNameLabel =
      new QLabel(QString("Active Interface: <b>%1</b>")
                     .arg(QString::fromStdString(manager->getInterfaceName())));
  layout->addWidget(ifNameLabel, row, 0, 1, 2);
  row++;

  QLabel *currentMacLabel = new QLabel("Current MAC Address:");
  currentMacValLabel =
      new QLabel(QString::fromStdString(manager->getCurrentMacAddress()));
  layout->addWidget(currentMacLabel, row, 0);
  layout->addWidget(currentMacValLabel, row, 1);
  row++;

  QLabel *newMacLabel = new QLabel("New MAC Address:");
  macAddressInput = new QLineEdit;
  macAddressInput->setPlaceholderText("02:aa:bb:cc:dd:ee");
  layout->addWidget(newMacLabel, row, 0);
  layout->addWidget(macAddressInput, row, 1);
  row++;

  QPushButton *genMacBtn = new QPushButton("Generate Random MAC");
  connect(genMacBtn, &QPushButton::clicked, [this]() {
    string randMac = manager->generateRandomMacAddress();
    macAddressInput->setText(QString::fromStdString(randMac));
  });

  QPushButton *applyMacBtn = new QPushButton("Apply MAC Address");
  connect(applyMacBtn, &QPushButton::clicked, [this]() {
    string targetMac = macAddressInput->text().toStdString();
    if (targetMac.empty()) {
      statusText->append("Error: Enter or generate a MAC address first.");
      return;
    }
    statusText->append(
        "Updating MAC address... this will temporarily drop connection.");
    bool ok = manager->setMacAddress(targetMac);
    if (ok) {
      currentMacValLabel->setText(
          QString::fromStdString(manager->getCurrentMacAddress()));
      statusText->append("Successfully spoofed MAC address.");
    } else {
      statusText->append("Failed to spoof MAC address. Make sure the "
                         "application has sudo/root permissions.");
    }
  });

  layout->addWidget(genMacBtn, row, 0);
  layout->addWidget(applyMacBtn, row, 1);
  row++;

  layout->setRowStretch(row, 1);

  tab->setLayout(layout);
  return tab;
}

void GUIMainWindow::updateVpnTable() {
  auto pool = manager->getVpnPool();
  if (!pool)
    return;

  auto profiles = pool->getProfiles();
  vpnTable->setRowCount(0);
  vpnTable->setRowCount(profiles.size());

  std::string activeName = pool->getActiveProfileName();
  if (activeName.empty()) {
    activeVpnLabel->setText("Active VPN: <b>None (Disconnected)</b>");
  } else {
    activeVpnLabel->setText(QString("Active VPN: <b>%1</b>")
                                .arg(QString::fromStdString(activeName)));
  }

  for (size_t i = 0; i < profiles.size(); ++i) {
    const auto &prof = profiles[i];
    QTableWidgetItem *nameItem =
        new QTableWidgetItem(QString::fromStdString(prof.name));
    QTableWidgetItem *typeItem =
        new QTableWidgetItem(QString::fromStdString(prof.type));
    QTableWidgetItem *pathItem =
        new QTableWidgetItem(QString::fromStdString(prof.configPath));

    bool isConnected = (prof.name == activeName && pool->isVPNConnected());
    QTableWidgetItem *statusItem =
        new QTableWidgetItem(isConnected ? "Connected" : "Disconnected");

    if (isConnected) {
      statusItem->setBackground(QBrush(QColor(230, 255, 230)));
      statusItem->setForeground(QBrush(QColor(0, 150, 0)));
    } else {
      statusItem->setBackground(QBrush(QColor(255, 230, 230)));
      statusItem->setForeground(QBrush(QColor(200, 0, 0)));
    }

    vpnTable->setItem(i, 0, nameItem);
    vpnTable->setItem(i, 1, typeItem);
    vpnTable->setItem(i, 2, pathItem);
    vpnTable->setItem(i, 3, statusItem);
  }
}

void GUIMainWindow::updateFeedList() {
  auto sync = manager->getThreatSync();
  if (!sync)
    return;

  feedListWidget->clear();
  auto feeds = sync->getFeedUrls();
  for (const auto &feed : feeds) {
    feedListWidget->addItem(QString::fromStdString(feed));
  }
}

void GUIMainWindow::updateThreatSyncStats() {
  auto sync = manager->getThreatSync();
  if (!sync)
    return;

  size_t count = sync->getThreatIPCount();
  threatIpCountLabel->setText(
      QString("Cached Threat IPs: <b>%1</b>").arg(count));
}

QWidget *GUIMainWindow::createQosTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QLabel *titleLabel =
      new QLabel("<b>Quality of Service (QoS) Bandwidth Shaper</b>");
  titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 10px;");
  layout->addWidget(titleLabel);

  qosTable = new QTableWidget;
  qosTable->setColumnCount(5);
  QStringList headers;
  headers << "ID" << "Type" << "Target Value" << "Direction" << "Rate Limit";
  qosTable->setHorizontalHeaderLabels(headers);
  qosTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  qosTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  qosTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  qosTable->setSelectionMode(QAbstractItemView::SingleSelection);
  layout->addWidget(qosTable);

  // Rule Control buttons
  QHBoxLayout *btnLayout = new QHBoxLayout;
  QPushButton *removeBtn = new QPushButton("Remove Selected Rule");
  connect(removeBtn, &QPushButton::clicked, [this]() {
    int row = qosTable->currentRow();
    if (row >= 0) {
      std::string id = qosTable->item(row, 0)->text().toStdString();
      bool ok = manager->getQosManager()->removeRule(id);
      if (ok) {
        statusText->append(
            QString("Removed QoS rule: %1").arg(QString::fromStdString(id)));
        updateQosTable();
      } else {
        statusText->append("Error: Could not remove selected QoS rule.");
      }
    } else {
      statusText->append("Error: Select a QoS rule from the table first.");
    }
  });

  QPushButton *clearBtn = new QPushButton("Clear All Rules");
  connect(clearBtn, &QPushButton::clicked, [this]() {
    manager->getQosManager()->clearRules();
    statusText->append("Cleared all traffic shaping rules.");
    updateQosTable();
  });

  QPushButton *reapplyBtn = new QPushButton("Reapply All Rules");
  connect(reapplyBtn, &QPushButton::clicked, [this]() {
    manager->getQosManager()->reapplyAllRules();
    statusText->append(
        "Reapplied all traffic shaping rules to network interface.");
    updateQosTable();
  });

  btnLayout->addWidget(removeBtn);
  btnLayout->addWidget(clearBtn);
  btnLayout->addWidget(reapplyBtn);
  layout->addLayout(btnLayout);

  // Add Rule Form
  QLabel *formTitle = new QLabel("<b>Add QoS Bandwidth Limit Rule:</b>");
  formTitle->setStyleSheet("margin-top: 15px;");
  layout->addWidget(formTitle);

  QGridLayout *formLayout = new QGridLayout;

  QLabel *typeLabel = new QLabel("Limit Type:");
  qosTypeCombo = new QComboBox;
  qosTypeCombo->addItems({"ip", "port"});

  QLabel *valueLabel = new QLabel("Target IP / Port:");
  qosValueInput = new QLineEdit;
  qosValueInput->setPlaceholderText("e.g. 192.168.1.100 or 80");

  QLabel *dirLabel = new QLabel("IP Direction:");
  qosDirCombo = new QComboBox;
  qosDirCombo->addItems({"src", "dst"});

  QLabel *rateLabel = new QLabel("Bandwidth Limit Rate:");
  qosRateInput = new QLineEdit;
  qosRateInput->setPlaceholderText("e.g. 10mbit, 512kbps");

  QPushButton *addBtn = new QPushButton("Add Bandwidth Limit");
  connect(addBtn, &QPushButton::clicked, [this]() {
    std::string type = qosTypeCombo->currentText().toStdString();
    std::string value = qosValueInput->text().toStdString();
    std::string direction = qosDirCombo->currentText().toStdString();
    std::string rate = qosRateInput->text().toStdString();

    if (value.empty() || rate.empty()) {
      statusText->append("Error: Fill Target Value and Rate fields.");
      return;
    }

    bool ok = manager->getQosManager()->addRule(type, value, direction, rate);
    if (ok) {
      statusText->append(QString("Added QoS limit: %1 to %2")
                             .arg(QString::fromStdString(rate),
                                  QString::fromStdString(value)));
      qosValueInput->clear();
      qosRateInput->clear();
      updateQosTable();
    } else {
      statusText->append("Failed to add QoS limit rule. Please verify inputs.");
    }
  });

  formLayout->addWidget(typeLabel, 0, 0);
  formLayout->addWidget(qosTypeCombo, 0, 1);
  formLayout->addWidget(valueLabel, 1, 0);
  formLayout->addWidget(qosValueInput, 1, 1);
  formLayout->addWidget(dirLabel, 2, 0);
  formLayout->addWidget(qosDirCombo, 2, 1);
  formLayout->addWidget(rateLabel, 3, 0);
  formLayout->addWidget(qosRateInput, 3, 1);
  formLayout->addWidget(addBtn, 4, 0, 1, 2);
  layout->addLayout(formLayout);

  // Disable direction selector when type is port
  connect(qosTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
          [this](int index) {
            qosDirCombo->setEnabled(index == 0); // Enabled only for 'ip'
          });

  tab->setLayout(layout);

  // Initial load
  updateQosTable();
  return tab;
}

void GUIMainWindow::updateQosTable() {
  auto qos = manager->getQosManager();
  if (!qos)
    return;

  auto rules = qos->getRules();
  qosTable->setRowCount(0);
  qosTable->setRowCount(rules.size());

  for (size_t i = 0; i < rules.size(); ++i) {
    const auto &rule = rules[i];
    qosTable->setItem(i, 0,
                      new QTableWidgetItem(QString::fromStdString(rule.id)));
    qosTable->setItem(i, 1,
                      new QTableWidgetItem(QString::fromStdString(rule.type)));
    qosTable->setItem(i, 2,
                      new QTableWidgetItem(QString::fromStdString(rule.value)));

    std::string dirStr = (rule.type == "ip") ? rule.direction : "N/A";
    qosTable->setItem(i, 3,
                      new QTableWidgetItem(QString::fromStdString(dirStr)));
    qosTable->setItem(i, 4,
                      new QTableWidgetItem(QString::fromStdString(rule.rate)));
  }
}

QWidget *GUIMainWindow::createDeviceMapperTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QLabel *titleLabel = new QLabel("<b>Network Topology & Passive Device Mapper</b>");
  titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 10px;");
  layout->addWidget(titleLabel);

  deviceTable = new QTableWidget;
  deviceTable->setColumnCount(5);
  QStringList headers;
  headers << "IP Address" << "MAC Address" << "Hostname" << "Interface" << "Status";
  deviceTable->setHorizontalHeaderLabels(headers);
  deviceTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  deviceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  deviceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  deviceTable->setSelectionMode(QAbstractItemView::SingleSelection);
  layout->addWidget(deviceTable);

  QHBoxLayout *btnLayout = new QHBoxLayout;
  QPushButton *scanBtn = new QPushButton("Scan Network Now");
  connect(scanBtn, &QPushButton::clicked, [this]() {
    auto dm = manager->getDeviceMapper();
    if (dm) {
      statusText->append("Triggering network device mapping scan...");
      std::thread([this, dm]() {
        dm->scanNow();
        QMetaObject::invokeMethod(this, [this]() {
          updateDeviceTable();
          statusText->append("Network device mapping scan completed.");
        });
      }).detach();
    }
  });

  QPushButton *blockBtn = new QPushButton("Block Selected Device");
  connect(blockBtn, &QPushButton::clicked, [this]() {
    int row = deviceTable->currentRow();
    if (row >= 0) {
      std::string ip = deviceTable->item(row, 0)->text().toStdString();
      if (ip == "127.0.0.1") {
        statusText->append("Error: Cannot block localhost (127.0.0.1).");
        return;
      }
      manager->blockIPAddress(ip);
      statusText->append(QString("Blocked device IP: %1").arg(QString::fromStdString(ip)));
    } else {
      statusText->append("Error: Select a device from the table first.");
    }
  });

  QPushButton *limitBtn = new QPushButton("Rate-Limit Selected (1 Mbps)");
  connect(limitBtn, &QPushButton::clicked, [this]() {
    int row = deviceTable->currentRow();
    if (row >= 0) {
      std::string ip = deviceTable->item(row, 0)->text().toStdString();
      auto qos = manager->getQosManager();
      if (qos) {
        bool ok = qos->addRule("ip", ip, "src", "1mbit");
        if (ok) {
          statusText->append(QString("Added QoS 1Mbit shaper rule for IP: %1").arg(QString::fromStdString(ip)));
          updateQosTable();
        } else {
          statusText->append("Failed to apply QoS shaper limit rule.");
        }
      }
    } else {
      statusText->append("Error: Select a device from the table first.");
    }
  });

  btnLayout->addWidget(scanBtn);
  btnLayout->addWidget(blockBtn);
  btnLayout->addWidget(limitBtn);
  layout->addLayout(btnLayout);

  tab->setLayout(layout);
  return tab;
}

QWidget *GUIMainWindow::createHoneypotTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QLabel *titleLabel = new QLabel("<b>Active Honeypot (Port-Trap Engine)</b>");
  titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 10px;");
  layout->addWidget(titleLabel);

  QHBoxLayout *statusLayout = new QHBoxLayout;
  honeypotStatusLabel = new QLabel("Honeypot Engine: <b>Inactive</b>");
  honeypotStatusLabel->setStyleSheet("font-size: 13px;");
  statusLayout->addWidget(honeypotStatusLabel);

  QPushButton *startBtn = new QPushButton("Start Engine");
  connect(startBtn, &QPushButton::clicked, [this]() {
    auto hm = manager->getHoneypotManager();
    if (hm) {
      hm->startHoneypot();
      statusText->append("Active Honeypot Engine started.");
      updateHoneypotTab();
    }
  });

  QPushButton *stopBtn = new QPushButton("Stop Engine");
  connect(stopBtn, &QPushButton::clicked, [this]() {
    auto hm = manager->getHoneypotManager();
    if (hm) {
      hm->stopHoneypot();
      statusText->append("Active Honeypot Engine stopped.");
      updateHoneypotTab();
    }
  });

  statusLayout->addWidget(startBtn);
  statusLayout->addWidget(stopBtn);
  layout->addLayout(statusLayout);

  QHBoxLayout *configLayout = new QHBoxLayout;
  
  QVBoxLayout *portsListCol = new QVBoxLayout;
  portsListCol->addWidget(new QLabel("<b>Trap Ports:</b>"));
  trapPortsList = new QListWidget;
  portsListCol->addWidget(trapPortsList);
  configLayout->addLayout(portsListCol);

  QVBoxLayout *portsCtrlCol = new QVBoxLayout;
  portsCtrlCol->addWidget(new QLabel("<b>Add Custom Trap Port:</b>"));
  addTrapPortSpin = new QSpinBox;
  addTrapPortSpin->setRange(1, 65535);
  addTrapPortSpin->setValue(8080);
  portsCtrlCol->addWidget(addTrapPortSpin);

  QPushButton *addPortBtn = new QPushButton("Add Port");
  connect(addPortBtn, &QPushButton::clicked, [this]() {
    auto hm = manager->getHoneypotManager();
    if (hm) {
      int port = addTrapPortSpin->value();
      if (hm->addTrapPort(port)) {
        statusText->append(QString("Added trap port: %1").arg(port));
        updateHoneypotTab();
      } else {
        statusText->append(QString("Failed to add port %1. Already trapped or invalid.").arg(port));
      }
    }
  });

  QPushButton *removePortBtn = new QPushButton("Remove Selected Port");
  connect(removePortBtn, &QPushButton::clicked, [this]() {
    auto hm = manager->getHoneypotManager();
    QListWidgetItem* item = trapPortsList->currentItem();
    if (hm && item) {
      int port = item->text().toInt();
      if (hm->removeTrapPort(port)) {
        statusText->append(QString("Removed trap port: %1").arg(port));
        updateHoneypotTab();
      } else {
        statusText->append("Failed to remove selected trap port.");
      }
    } else {
      statusText->append("Error: Select a port from the list first.");
    }
  });

  portsCtrlCol->addWidget(addPortBtn);
  portsCtrlCol->addWidget(removePortBtn);
  portsCtrlCol->addStretch();
  configLayout->addLayout(portsCtrlCol);

  layout->addLayout(configLayout);

  layout->addWidget(new QLabel("<b>Attack & Intrusion Trigger History (Auto-Blocked Hosts):</b>"));
  honeypotTriggerTable = new QTableWidget;
  honeypotTriggerTable->setColumnCount(4);
  QStringList gridHeaders;
  gridHeaders << "Timestamp" << "Violator IP" << "Targeted Port" << "Status";
  honeypotTriggerTable->setHorizontalHeaderLabels(gridHeaders);
  honeypotTriggerTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  honeypotTriggerTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  honeypotTriggerTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  layout->addWidget(honeypotTriggerTable);

  QPushButton *clearTrigBtn = new QPushButton("Clear History Logs");
  connect(clearTrigBtn, &QPushButton::clicked, [this]() {
    auto hm = manager->getHoneypotManager();
    if (hm) {
      hm->clearTriggers();
      statusText->append("Intrusion trigger history cleared.");
      updateHoneypotTab();
    }
  });
  layout->addWidget(clearTrigBtn);

  tab->setLayout(layout);
  return tab;
}

void GUIMainWindow::updateDeviceTable() {
  auto dm = manager->getDeviceMapper();
  if (!dm)
    return;

  auto devices = dm->getDevices();
  deviceTable->setRowCount(0);
  deviceTable->setRowCount(devices.size());

  for (size_t i = 0; i < devices.size(); ++i) {
    const auto &dev = devices[i];
    
    QTableWidgetItem *ipItem = new QTableWidgetItem(QString::fromStdString(dev.ip));
    QTableWidgetItem *macItem = new QTableWidgetItem(QString::fromStdString(dev.mac));
    QTableWidgetItem *hostItem = new QTableWidgetItem(QString::fromStdString(dev.hostname));
    QTableWidgetItem *ifItem = new QTableWidgetItem(QString::fromStdString(dev.interface));
    
    QTableWidgetItem *statusItem = new QTableWidgetItem(dev.isOnline ? "Online" : "Offline");
    if (dev.isOnline) {
      statusItem->setBackground(QBrush(QColor(230, 255, 230)));
      statusItem->setForeground(QBrush(QColor(0, 150, 0)));
    } else {
      statusItem->setBackground(QBrush(QColor(255, 230, 230)));
      statusItem->setForeground(QBrush(QColor(200, 0, 0)));
    }

    deviceTable->setItem(i, 0, ipItem);
    deviceTable->setItem(i, 1, macItem);
    deviceTable->setItem(i, 2, hostItem);
    deviceTable->setItem(i, 3, ifItem);
    deviceTable->setItem(i, 4, statusItem);
  }
}

void GUIMainWindow::updateHoneypotTab() {
  auto hm = manager->getHoneypotManager();
  if (!hm)
    return;

  if (hm->isRunning()) {
    honeypotStatusLabel->setText("Honeypot Engine: <b style='color:green;'>Active (Listening)</b>");
  } else {
    honeypotStatusLabel->setText("Honeypot Engine: <b style='color:red;'>Inactive (Stopped)</b>");
  }

  int currentSelRow = trapPortsList->currentRow();
  trapPortsList->clear();
  auto ports = hm->getTrapPorts();
  for (int p : ports) {
    trapPortsList->addItem(QString::number(p));
  }
  if (currentSelRow >= 0 && currentSelRow < trapPortsList->count()) {
    trapPortsList->setCurrentRow(currentSelRow);
  }

  auto triggers = hm->getTriggers();
  honeypotTriggerTable->setRowCount(0);
  honeypotTriggerTable->setRowCount(triggers.size());

  for (size_t i = 0; i < triggers.size(); ++i) {
    const auto &trig = triggers[i];
    
    QTableWidgetItem *timeItem = new QTableWidgetItem(QString::fromStdString(trig.timestamp));
    QTableWidgetItem *ipItem = new QTableWidgetItem(QString::fromStdString(trig.violatorIP));
    QTableWidgetItem *portItem = new QTableWidgetItem(QString::number(trig.port));
    
    QTableWidgetItem *statusItem = new QTableWidgetItem(QString::fromStdString(trig.status));
    statusItem->setBackground(QBrush(QColor(255, 230, 230)));
    statusItem->setForeground(QBrush(QColor(200, 0, 0)));
    statusItem->setTextAlignment(Qt::AlignCenter);

    honeypotTriggerTable->setItem(i, 0, timeItem);
    honeypotTriggerTable->setItem(i, 1, ipItem);
    honeypotTriggerTable->setItem(i, 2, portItem);
    honeypotTriggerTable->setItem(i, 3, statusItem);
  }
}

QWidget *GUIMainWindow::createIpsTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QLabel *titleLabel = new QLabel("<b>Intrusion Prevention System (IPS) Signature Engine</b>");
  titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 10px;");
  layout->addWidget(titleLabel);

  layout->addWidget(new QLabel("<b>Active IPS Rules:</b>"));
  ipsRulesTable = new QTableWidget;
  ipsRulesTable->setColumnCount(7);
  QStringList rulesHeaders;
  rulesHeaders << "SID" << "Action" << "Proto" << "Source IP/Port" << "Dest IP/Port" << "Alert Message" << "Status";
  ipsRulesTable->setHorizontalHeaderLabels(rulesHeaders);
  ipsRulesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  ipsRulesTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  ipsRulesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  ipsRulesTable->setSelectionMode(QAbstractItemView::SingleSelection);
  layout->addWidget(ipsRulesTable);

  QHBoxLayout *ruleBtnLayout = new QHBoxLayout;
  QPushButton *toggleRuleBtn = new QPushButton("Enable/Disable Selected");
  connect(toggleRuleBtn, &QPushButton::clicked, [this]() {
    int row = ipsRulesTable->currentRow();
    if (row >= 0) {
      int sid = ipsRulesTable->item(row, 0)->text().toInt();
      auto ips = manager->getIpsEngine();
      if (ips) {
        auto rules = ips->getRules();
        for (const auto& r : rules) {
          if (r.sid == sid) {
            ips->toggleRule(sid, !r.enabled);
            statusText->append(QString("Toggled IPS rule SID %1.").arg(sid));
            updateIpsTable();
            break;
          }
        }
      }
    } else {
      statusText->append("Error: Select a rule from the table first.");
    }
  });

  QPushButton *deleteRuleBtn = new QPushButton("Delete Selected Rule");
  connect(deleteRuleBtn, &QPushButton::clicked, [this]() {
    int row = ipsRulesTable->currentRow();
    if (row >= 0) {
      int sid = ipsRulesTable->item(row, 0)->text().toInt();
      auto ips = manager->getIpsEngine();
      if (ips) {
        if (ips->deleteRule(sid)) {
          statusText->append(QString("Deleted IPS rule SID %1.").arg(sid));
          updateIpsTable();
        } else {
          statusText->append("Error: Could not delete rule.");
        }
      }
    } else {
      statusText->append("Error: Select a rule from the table first.");
    }
  });

  ruleBtnLayout->addWidget(toggleRuleBtn);
  ruleBtnLayout->addWidget(deleteRuleBtn);
  layout->addLayout(ruleBtnLayout);

  layout->addWidget(new QLabel("<b>Add Snort-Style Rule:</b>"));
  QHBoxLayout *formLayout = new QHBoxLayout;
  ipsRuleInput = new QLineEdit;
  ipsRuleInput->setPlaceholderText("drop tcp any any -> any 80 (msg:\"Forbidden content\"; content:\"malware\"; sid:999;)");
  QPushButton *addRuleBtn = new QPushButton("Compile & Add Rule");
  connect(addRuleBtn, &QPushButton::clicked, [this]() {
    std::string ruleStr = ipsRuleInput->text().toStdString();
    auto ips = manager->getIpsEngine();
    if (ips) {
      if (ips->addRule(ruleStr)) {
        statusText->append("Successfully compiled and added IPS rule.");
        ipsRuleInput->clear();
        updateIpsTable();
      } else {
        statusText->append("Error: Failed to compile rule. Verify syntax.");
      }
    }
  });
  formLayout->addWidget(ipsRuleInput);
  formLayout->addWidget(addRuleBtn);
  layout->addLayout(formLayout);

  layout->addWidget(new QLabel("<b>IPS Security Alerts Log:</b>"));
  ipsAlertsTable = new QTableWidget;
  ipsAlertsTable->setColumnCount(6);
  QStringList alertHeaders;
  alertHeaders << "Timestamp" << "SID" << "Source IP" << "Target Port" << "Message" << "Action";
  ipsAlertsTable->setHorizontalHeaderLabels(alertHeaders);
  ipsAlertsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  ipsAlertsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  ipsAlertsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  layout->addWidget(ipsAlertsTable);

  QPushButton *clearAlertsBtn = new QPushButton("Clear Alerts History");
  connect(clearAlertsBtn, &QPushButton::clicked, [this]() {
    auto ips = manager->getIpsEngine();
    if (ips) {
      ips->clearAlerts();
      statusText->append("IPS Alerts history cleared.");
      updateIpsTable();
    }
  });
  layout->addWidget(clearAlertsBtn);

  tab->setLayout(layout);
  return tab;
}

void GUIMainWindow::updateIpsTable() {
  auto ips = manager->getIpsEngine();
  if (!ips) return;

  auto rules = ips->getRules();
  ipsRulesTable->setRowCount(0);
  ipsRulesTable->setRowCount(rules.size());

  for (size_t i = 0; i < rules.size(); ++i) {
    const auto &rule = rules[i];
    
    QTableWidgetItem *sidItem = new QTableWidgetItem(QString::number(rule.sid));
    QTableWidgetItem *actionItem = new QTableWidgetItem(QString::fromStdString(rule.action));
    QTableWidgetItem *protoItem = new QTableWidgetItem(QString::fromStdString(rule.protocol));
    
    std::string srcStr = rule.srcIp + ":" + (rule.srcPort == 0 ? "any" : std::to_string(rule.srcPort));
    QTableWidgetItem *srcItem = new QTableWidgetItem(QString::fromStdString(srcStr));
    
    std::string destStr = rule.destIp + ":" + (rule.destPort == 0 ? "any" : std::to_string(rule.destPort));
    QTableWidgetItem *destItem = new QTableWidgetItem(QString::fromStdString(destStr));
    
    QTableWidgetItem *msgItem = new QTableWidgetItem(QString::fromStdString(rule.message));
    
    QTableWidgetItem *statusItem = new QTableWidgetItem(rule.enabled ? "Active" : "Disabled");
    if (rule.enabled) {
      statusItem->setBackground(QBrush(QColor(230, 255, 230)));
      statusItem->setForeground(QBrush(QColor(0, 150, 0)));
    } else {
      statusItem->setBackground(QBrush(QColor(240, 240, 240)));
      statusItem->setForeground(QBrush(QColor(120, 120, 120)));
    }
    
    ipsRulesTable->setItem(i, 0, sidItem);
    ipsRulesTable->setItem(i, 1, actionItem);
    ipsRulesTable->setItem(i, 2, protoItem);
    ipsRulesTable->setItem(i, 3, srcItem);
    ipsRulesTable->setItem(i, 4, destItem);
    ipsRulesTable->setItem(i, 5, msgItem);
    ipsRulesTable->setItem(i, 6, statusItem);
  }

  auto alerts = ips->getAlerts();
  ipsAlertsTable->setRowCount(0);
  ipsAlertsTable->setRowCount(alerts.size());

  for (size_t i = 0; i < alerts.size(); ++i) {
    const auto &alert = alerts[i];
    
    QTableWidgetItem *timeItem = new QTableWidgetItem(QString::fromStdString(alert.timestamp));
    QTableWidgetItem *sidItem = new QTableWidgetItem(QString::number(alert.sid));
    QTableWidgetItem *ipItem = new QTableWidgetItem(QString::fromStdString(alert.violatorIP));
    QTableWidgetItem *portItem = new QTableWidgetItem(QString::number(alert.targetedPort));
    QTableWidgetItem *msgItem = new QTableWidgetItem(QString::fromStdString(alert.message));
    
    QTableWidgetItem *actItem = new QTableWidgetItem(QString::fromStdString(alert.action));
    if (alert.action == "Blocked") {
      actItem->setBackground(QBrush(QColor(255, 230, 230)));
      actItem->setForeground(QBrush(QColor(200, 0, 0)));
    } else {
      actItem->setBackground(QBrush(QColor(255, 245, 220)));
      actItem->setForeground(QBrush(QColor(200, 100, 0)));
    }
    actItem->setTextAlignment(Qt::AlignCenter);

    ipsAlertsTable->setItem(i, 0, timeItem);
    ipsAlertsTable->setItem(i, 1, sidItem);
    ipsAlertsTable->setItem(i, 2, ipItem);
    ipsAlertsTable->setItem(i, 3, portItem);
    ipsAlertsTable->setItem(i, 4, msgItem);
    ipsAlertsTable->setItem(i, 5, actItem);
  }
}

QWidget *GUIMainWindow::createDpiTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QLabel *titleLabel = new QLabel("<b>Deep Packet Inspection (DPI) & Protocol Analytics</b>");
  titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 10px;");
  layout->addWidget(titleLabel);

  layout->addWidget(new QLabel("<b>Application Protocol Traffic Breakdown:</b>"));
  dpiTable = new QTableWidget;
  dpiTable->setColumnCount(4);
  QStringList headers;
  headers << "Protocol" << "Packet Count" << "Total Traffic (Bytes)" << "Traffic share (%)";
  dpiTable->setHorizontalHeaderLabels(headers);
  dpiTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
  dpiTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  dpiTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  layout->addWidget(dpiTable);

  QHBoxLayout *btnLayout = new QHBoxLayout;
  QPushButton *clearBtn = new QPushButton("Clear Classification Stats");
  connect(clearBtn, &QPushButton::clicked, [this]() {
    auto dpi = manager->getDpiClassifier();
    if (dpi) {
      dpi->clearStats();
      statusText->append("DPI classification statistics cleared.");
      updateDpiTable();
    }
  });

  btnLayout->addWidget(clearBtn);
  btnLayout->addStretch();
  layout->addLayout(btnLayout);

  tab->setLayout(layout);
  return tab;
}

void GUIMainWindow::updateDpiTable() {
  auto dpi = manager->getDpiClassifier();
  if (!dpi) return;

  auto stats = dpi->getStats();
  dpiTable->setRowCount(0);
  dpiTable->setRowCount(stats.size());

  unsigned long long overallBytes = 0;
  for (const auto& pair : stats) {
    overallBytes += pair.second.totalBytes;
  }

  int row = 0;
  for (const auto& pair : stats) {
    const auto &stat = pair.second;
    
    QTableWidgetItem *protoItem = new QTableWidgetItem(QString::fromStdString(stat.name));
    QTableWidgetItem *packetsItem = new QTableWidgetItem(QString::number(stat.packetCount));
    
    QString bytesStr;
    if (stat.totalBytes < 1024) {
      bytesStr = QString("%1 B").arg(stat.totalBytes);
    } else if (stat.totalBytes < 1024 * 1024) {
      bytesStr = QString("%1 KB").arg(QString::number(stat.totalBytes / 1024.0, 'f', 2));
    } else {
      bytesStr = QString("%1 MB").arg(QString::number(stat.totalBytes / (1024.0 * 1024.0), 'f', 2));
    }
    QTableWidgetItem *bytesItem = new QTableWidgetItem(bytesStr);

    double percent = 0.0;
    if (overallBytes > 0) {
      percent = (static_cast<double>(stat.totalBytes) / overallBytes) * 100.0;
    }
    
    QTableWidgetItem *percentItem = new QTableWidgetItem(QString("%1%").arg(QString::number(percent, 'f', 1)));
    percentItem->setTextAlignment(Qt::AlignCenter);

    if (stat.name == "TLS/SSL") {
      protoItem->setForeground(QBrush(QColor(0, 102, 204)));
    } else if (stat.name == "HTTP") {
      protoItem->setForeground(QBrush(QColor(0, 153, 76)));
    } else if (stat.name == "SSH") {
      protoItem->setForeground(QBrush(QColor(153, 0, 153)));
    } else if (stat.name == "DNS") {
      protoItem->setForeground(QBrush(QColor(204, 102, 0)));
    }

    dpiTable->setItem(row, 0, protoItem);
    dpiTable->setItem(row, 1, packetsItem);
    dpiTable->setItem(row, 2, bytesItem);
    dpiTable->setItem(row, 3, percentItem);
    row++;
  }
}

QWidget *GUIMainWindow::createTopologyTab() {
  QWidget *tab = new QWidget;
  QVBoxLayout *layout = new QVBoxLayout;

  QLabel *titleLabel = new QLabel("<b>Dynamic Network Topology Graphic Mapper</b>");
  titleLabel->setStyleSheet("font-size: 14px; margin-bottom: 5px;");
  layout->addWidget(titleLabel);

  layout->addWidget(new QLabel("<i>Double-click any node to block or rate-limit the device. Active flows are animated in real-time.</i>"));

  topologyWidget = new TopologyWidget(manager, this);
  layout->addWidget(topologyWidget);

  QHBoxLayout *btnLayout = new QHBoxLayout;
  QPushButton *refreshBtn = new QPushButton("Refresh Topology Map");
  connect(refreshBtn, &QPushButton::clicked, [this]() {
    updateTopologyTab();
    statusText->append("Network topology map refreshed.");
  });
  btnLayout->addWidget(refreshBtn);
  btnLayout->addStretch();
  layout->addLayout(btnLayout);

  tab->setLayout(layout);
  return tab;
}

void GUIMainWindow::updateTopologyTab() {
  if (topologyWidget) {
    topologyWidget->updateTopology();
  }
}