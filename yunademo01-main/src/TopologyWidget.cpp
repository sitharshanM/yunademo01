#include "TopologyWidget.h"
#include "FirewallManager.h"
#include "QosManager.h"
#include <QMessageBox>
#include <QBrush>
#include <QPen>
#include <QColor>
#include <QLineF>
#include <QPointF>
#include <cmath>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// DeviceNodeItem Implementation
DeviceNodeItem::DeviceNodeItem(const std::string& ipAddr, const std::string& host, bool isGw, FirewallManager* mgr, QGraphicsItem* parent)
    : QGraphicsEllipseItem(-20, -20, 40, 40, parent), ip(ipAddr), hostname(host), isGateway(isGw), manager(mgr), labelItem(nullptr) {
    
    setFlag(QGraphicsItem::ItemIsMovable);
    setFlag(QGraphicsItem::ItemSendsScenePositionChanges);

    // Styling
    QColor color;
    if (isGateway) {
        color = QColor(255, 128, 0); // Orange for Gateway Router
    } else {
        // Check if blocked
        // We look at FirewallManager blockedIPs or similar (we can query it)
        std::string status = manager->getStatus();
        // Since blockedIPs is a private member, we can check if it is in FirewallManager blockedIPs list
        // FirewallManager exposes respondToThreat and blockIPAddress, we check if IP is in the status text
        // Or we can check if blocked via checking if it blocks connections.
        // A simple way is to check if it's already blocked: we can call blockIPAddress on it
        // Or just let FirewallManager handle it. Let's make it green by default, red if blocked.
        // Wait, FirewallManager has a status or blockedIPs vector? Yes! blockedIPs list in FirewallManager
        // Since we don't have a direct public getter for blockedIPs, we can check getStatus() contains the IP,
        // or just maintain a green/red visual color. Let's write a simple helper in FirewallManager or check status.
        if (status.find(ip) != std::string::npos) {
            color = QColor(255, 51, 51); // Red if blocked
        } else {
            color = QColor(51, 204, 51); // Green if active/online
        }
    }

    setBrush(QBrush(color));
    setPen(QPen(QColor(40, 40, 40), 2));
}

void DeviceNodeItem::mouseDoubleClickEvent(QGraphicsSceneMouseEvent *event) {
    (void)event;
    if (isGateway) {
        QMessageBox::information(nullptr, "Gateway Node", "This is the primary gateway router.\nIP Address: " + QString::fromStdString(ip));
        return;
    }

    QMessageBox msgBox;
    msgBox.setWindowTitle("Configure Device: " + QString::fromStdString(hostname));
    msgBox.setText(QString("Device IP: %1\nMAC Address: %2\n\nWhat action would you like to perform?").arg(QString::fromStdString(ip), QString::fromStdString(hostname)));
    
    QPushButton *blockButton = msgBox.addButton("Block IP Address", QMessageBox::ActionRole);
    QPushButton *limitButton = msgBox.addButton("Rate-Limit (1 Mbps)", QMessageBox::ActionRole);
    QPushButton *cancelButton = msgBox.addButton(QMessageBox::Cancel);

    msgBox.exec();

    if (msgBox.clickedButton() == blockButton) {
        if (ip == "127.0.0.1") {
            QMessageBox::warning(nullptr, "Error", "Cannot block localhost (127.0.0.1).");
            return;
        }
        manager->blockIPAddress(ip);
        QMessageBox::information(nullptr, "Action Enforced", "Successfully blocked IP: " + QString::fromStdString(ip));
        // Repaint red
        setBrush(QBrush(QColor(255, 51, 51)));
    } else if (msgBox.clickedButton() == limitButton) {
        auto qos = manager->getQosManager();
        if (qos) {
            if (qos->addRule("ip", ip, "src", "1mbit")) {
                QMessageBox::information(nullptr, "Action Enforced", "Successfully applied 1 Mbps shaper to: " + QString::fromStdString(ip));
            } else {
                QMessageBox::warning(nullptr, "Error", "Failed to apply QoS rule.");
            }
        }
    }
}


// TopologyWidget Implementation
TopologyWidget::TopologyWidget(FirewallManager* mgr, QWidget* parent)
    : QGraphicsView(parent), manager(mgr), scene(new QGraphicsScene(this)), pulseTimer(nullptr) {
    
    setScene(scene);
    setRenderHint(QPainter::Antialiasing);
    setRenderHint(QPainter::TextAntialiasing);
    
    // Smooth pulse animation timer
    pulseTimer = new QTimer(this);
    connect(pulseTimer, &QTimer::timeout, this, &TopologyWidget::stepTrafficPulses);
    pulseTimer->start(50); // 20 FPS
}

TopologyWidget::~TopologyWidget() {
    clearScene();
}

void TopologyWidget::clearScene() {
    if (pulseTimer) pulseTimer->stop();
    
    for (auto& flow : flowLines) {
        scene->removeItem(flow.line);
        scene->removeItem(flow.pulse);
        delete flow.line;
        delete flow.pulse;
    }
    flowLines.clear();

    for (auto& pair : nodeItems) {
        scene->removeItem(pair.second);
        delete pair.second;
    }
    nodeItems.clear();

    for (auto& pair : labelItems) {
        scene->removeItem(pair.second);
        delete pair.second;
    }
    labelItems.clear();

    scene->clear();
}

void TopologyWidget::updateTopology() {
    clearScene();

    auto mapper = manager->getDeviceMapper();
    if (!mapper) return;

    auto devices = mapper->getDevices();
    if (devices.empty()) return;

    // 1. Position Router (Gateway) at the center
    std::string gatewayIp = "192.168.1.1";
    std::string gatewayHost = "Router";
    
    // Try to find if gateway exists in discovered devices
    for (const auto& dev : devices) {
        if (dev.ip.substr(dev.ip.find_last_of('.') + 1) == "1") {
            gatewayIp = dev.ip;
            gatewayHost = dev.hostname;
            break;
        }
    }

    DeviceNodeItem* gwNode = new DeviceNodeItem(gatewayIp, gatewayHost, true, manager);
    gwNode->setPos(0, -50);
    scene->addItem(gwNode);
    nodeItems[gatewayIp] = gwNode;

    QGraphicsTextItem* gwLabel = scene->addText(QString::fromStdString(gatewayHost + " (" + gatewayIp + ")"));
    gwLabel->setPos(-50, -90);
    gwLabel->setDefaultTextColor(QColor(50, 50, 50));
    labelItems[gatewayIp] = gwLabel;

    // 2. Position other devices in a circle around the gateway
    std::vector<NetworkDevice> clientDevices;
    for (const auto& dev : devices) {
        if (dev.ip != gatewayIp) {
            clientDevices.push_back(dev);
        }
    }

    size_t count = clientDevices.size();
    double radius = 180.0;
    
    for (size_t i = 0; i < count; ++i) {
        const auto& dev = clientDevices[i];
        
        double angle = (2.0 * M_PI * i) / (count > 0 ? count : 1);
        double x = radius * std::cos(angle);
        double y = radius * std::sin(angle) - 50.0; // Offset relative to center

        DeviceNodeItem* clientNode = new DeviceNodeItem(dev.ip, dev.hostname, false, manager);
        clientNode->setPos(x, y);
        scene->addItem(clientNode);
        nodeItems[dev.ip] = clientNode;

        QGraphicsTextItem* label = scene->addText(QString::fromStdString(dev.hostname + "\n(" + dev.ip + ")"));
        label->setPos(x - 50, y + 22);
        label->setDefaultTextColor(QColor(80, 80, 80));
        labelItems[dev.ip] = label;
    }

    // 3. Draw communication links
    // We inspect recent connections in FirewallManager to draw lines between communicating hosts
    // Standard connection lines: draw grey lines from gateway router to all connected clients
    for (const auto& pair : nodeItems) {
        if (pair.first != gatewayIp) {
            QGraphicsLineItem* line = scene->addLine(QLineF(gwNode->pos(), pair.second->pos()));
            
            // Highlight connections that have active packets
            bool hasActiveTraffic = false;
            // Iterate connection table to see if traffic exists for this IP
            // We can match sourceIP == pair.first
            auto recentPackets = manager->getRecentPackets();
            for (const auto& pkt : recentPackets) {
                if (pkt.sourceIP == pair.first || pkt.destIP == pair.first) {
                    hasActiveTraffic = true;
                    break;
                }
            }

            QPen pen;
            if (hasActiveTraffic) {
                pen = QPen(QColor(0, 153, 255), 2, Qt::SolidLine); // Blue active line
                
                // Add animated pulse dot
                QGraphicsEllipseItem* pulse = scene->addEllipse(-4, -4, 8, 8);
                pulse->setBrush(QBrush(QColor(255, 255, 51))); // Yellow pulse dot
                pulse->setPen(Qt::NoPen);
                pulse->setPos(gwNode->pos());

                ActiveFlowLine flow;
                flow.line = line;
                flow.pulse = pulse;
                flow.progress = 0.0;
                flowLines.push_back(flow);
            } else {
                pen = QPen(QColor(200, 200, 200), 1, Qt::DashLine); // Dashed grey line
            }
            line->setPen(pen);
            // Move lines to back so nodes are drawn on top
            line->setZValue(-1);
        }
    }

    // Set scene rect
    scene->setSceneRect(-280, -280, 560, 560);
    
    if (!flowLines.empty() && pulseTimer) {
        pulseTimer->start(50);
    }
}

void TopologyWidget::stepTrafficPulses() {
    for (auto& flow : flowLines) {
        flow.progress += 0.05; // 20 steps to reach end
        if (flow.progress > 1.0) {
            flow.progress = 0.0;
        }
        
        QLineF line = flow.line->line();
        QPointF nextPos = line.pointAt(flow.progress);
        flow.pulse->setPos(nextPos);
    }
}
