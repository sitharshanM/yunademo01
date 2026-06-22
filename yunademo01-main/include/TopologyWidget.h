#ifndef TOPOLOGY_WIDGET_H
#define TOPOLOGY_WIDGET_H

#include <QGraphicsView>
#include <QGraphicsScene>
#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsTextItem>
#include <QGraphicsSceneMouseEvent>
#include <QTimer>
#include <map>
#include <string>
#include <vector>

class FirewallManager;

class DeviceNodeItem : public QGraphicsEllipseItem {
private:
    std::string ip;
    std::string hostname;
    bool isGateway;
    FirewallManager* manager;
    QGraphicsTextItem* labelItem;

public:
    DeviceNodeItem(const std::string& ip, const std::string& hostname, bool isGateway, FirewallManager* mgr, QGraphicsItem* parent = nullptr);
    void setLabel(QGraphicsTextItem* label) { labelItem = label; }
    std::string getIp() const { return ip; }
    std::string getHostname() const { return hostname; }
    bool getIsGateway() const { return isGateway; }

protected:
    void mouseDoubleClickEvent(QGraphicsSceneMouseEvent *event) override;
};

class TopologyWidget : public QGraphicsView {
    Q_OBJECT
private:
    FirewallManager* manager;
    QGraphicsScene* scene;
    std::map<std::string, DeviceNodeItem*> nodeItems;
    std::map<std::string, QGraphicsTextItem*> labelItems;
    
    struct ActiveFlowLine {
        QGraphicsLineItem* line;
        QGraphicsEllipseItem* pulse;
        double progress; // 0.0 to 1.0
    };
    std::vector<ActiveFlowLine> flowLines;
    QTimer* pulseTimer;

    void clearScene();

public:
    explicit TopologyWidget(FirewallManager* mgr, QWidget* parent = nullptr);
    ~TopologyWidget();

    void updateTopology();

private slots:
    void stepTrafficPulses();
};

#endif // TOPOLOGY_WIDGET_H
