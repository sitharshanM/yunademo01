#ifndef IPS_ENGINE_H
#define IPS_ENGINE_H

#include <string>
#include <vector>
#include <mutex>
#include <atomic>

struct IpsRule {
    int sid = 0;
    std::string action = "alert"; // "alert", "drop"
    std::string protocol = "any";  // "tcp", "udp", "icmp", "any"
    std::string srcIp = "any";
    int srcPort = 0;               // 0 means any
    std::string destIp = "any";
    int destPort = 0;              // 0 means any
    std::string pattern;           // content to match
    std::string message;
    bool enabled = true;
};

struct IpsAlertRecord {
    std::string timestamp;
    int sid = 0;
    std::string message;
    std::string violatorIP;
    int targetedPort = 0;
    std::string action = "Alerted"; // "Alerted", "Blocked"
};

class IpsEngine {
private:
    std::vector<IpsRule> rules;
    std::vector<IpsAlertRecord> alerts;
    std::mutex ipsMutex;
    std::string rulesFilePath;
    std::string alertsFilePath;

    void loadRules();
    void saveRules();
    void loadAlerts();
    void saveAlerts();
    std::string getCurrentTimestamp();
    bool matchIp(const std::string& pattern, const std::string& ip);
    bool matchPort(int rulePort, int packetPort);

public:
    IpsEngine();
    ~IpsEngine();

    bool addRule(const std::string& ruleStr);
    bool deleteRule(int sid);
    void toggleRule(int sid, bool enabled);
    std::vector<IpsRule> getRules();

    bool inspectPacket(const std::string& protocol, const std::string& srcIp, int srcPort,
                       const std::string& destIp, int destPort, const std::string& payload,
                       IpsRule& matchedRule);

    std::vector<IpsAlertRecord> getAlerts();
    void clearAlerts();
    void logAlert(const IpsRule& rule, const std::string& violatorIP, int port);
};

#endif // IPS_ENGINE_H
