#ifndef FIREWALL_MANAGER_H
#define FIREWALL_MANAGER_H

#include "Common.h"
#include "NeuralNetwork.h"
#include "PacketSniffer.h"
#include "ThreatIntelligenceIntegrator.h"
#include "VPNPoolManager.h"
#include "ThreatIntelSynchronizer.h"
#include "QosManager.h"
#include "DeviceMapper.h"
#include "HoneypotManager.h"
#include "IpsEngine.h"
#include "DpiClassifier.h"
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <memory>
#include <curl/curl.h>

struct KnockState {
    int currentStep = 0;
    std::chrono::steady_clock::time_point lastKnockTime;
};

class FirewallManager {
private:
    std::unique_ptr<NeuralNetwork> neuralNetwork;
    std::vector<std::vector<double>> trainingData;
    std::vector<std::vector<double>> trainingLabels;
    std::map<std::string, ConnectionState> connectionTable;
    std::unordered_map<std::string, int> ipConnectionCounts;
    std::set<std::string> blockedIPs;
    std::map<std::string, BlockedDomain> blockedDomains;
    bool panicModeEnabled = false;
    bool internetStatus = false;
    CURL* curl;
    PacketSniffer sniffer;
    ThreatIntelligenceIntegrator threatIntel;
    std::unique_ptr<VPNPoolManager> vpnPool;
    std::unique_ptr<ThreatIntelSynchronizer> threatSync;
    std::unique_ptr<QosManager> qosManager;
    std::unique_ptr<DeviceMapper> deviceMapper;
    std::unique_ptr<HoneypotManager> honeypotManager;
    std::unique_ptr<IpsEngine> ipsEngine;
    std::unique_ptr<DpiClassifier> dpiClassifier;
    std::thread threatMonitorThread;
    std::thread maintenanceThread;
    std::condition_variable cv;
    std::queue<NetworkTrafficData> trafficQueue;
    std::string webhookUrl;
    std::map<std::string, CategorySchedule> categorySchedules;
    std::vector<LivePacketRecord> recentPackets;
    std::string interfaceName;

    std::map<std::string, KnockState> knockStates;
    std::vector<int> knockSequence = {7777, 8888, 9999};
    int knockWindowSeconds = 10;
    int knockTargetPort = 22;
    int knockOpenDurationSeconds = 60;
    bool dnsSinkholeEnabled = true;

    void checkPortKnock(const std::string& sourceIP, int destPort);
    void openPortForIP(const std::string& ip, int port);
    void closePortForIP(const std::string& ip, int port);

    std::string executeSystemCommand(const std::string& cmd);
    void initializeNeuralNetwork();
    void loadBlockedIPs();
    void saveBlockedIPs();
    void loadBlockedDomains();
    void saveBlockedDomains();
    void loadConfig();
    void saveConfig();
    void sendWebhookPayload(const std::string& title, const std::string& message);
    void checkSchedules();
    std::string getDomainCategory(const std::string& domain);
    void threatMonitor();
    void systemMaintenance();
    NetworkFeatures extractFeatures(const ConnectionState& connection);
    
    bool isValidIP(const std::string& ip);
    bool isValidDomain(const std::string& domain);
    bool isValidPort(const std::string& port);
    std::string sanitizeShellArg(const std::string& arg);

public:
    FirewallManager(const std::string& interface = "eth0");
    ~FirewallManager();

    void blockIPAddress(const std::string& ip);
    void unblockIPAddress(const std::string& ip);
    void blockWebsite(const std::string& website);
    void blockDomain(const std::string& domain, const std::string& category = "");
    void unblockDomain(const std::string& domain);
    void blockCategory(const std::string& category);
    void unblockCategory(const std::string& category);
    bool addFirewallRule(const std::string& action, const std::string& direction, 
                        const std::string& source, const std::string& destination, 
                        const std::string& protocol);
    bool removeFirewallRule(const std::string& action, const std::string& direction, 
                          const std::string& source, const std::string& destination, 
                          const std::string& protocol);
    void addNatRule(const std::string& sourceIP, const std::string& destIP, const std::string& port);
    void removeNatRule(const std::string& ruleID);
    void blockAllTraffic();
    void unblockAllTraffic();
    void sendNotification(const std::string& title, const std::string& message);
    void ruleViolationDetected(const std::string& rule, const std::string& violationDetail);
    void checkInternetConnectivity();
    void connectToVpn(const std::string& configPath);
    void disconnectVpn();
    void getGeoIP(const std::string& ip);
    void cleanupExpiredConnections();
    void trainNeuralNetwork();
    void autoHeal();
    bool detectThreat();
    void respondToThreat(const std::string& ip);
    void restoreDefaultConfig();
    std::string getStatus();
    void optimizeFirewallRules();
    void checkFirewallHealth();
    void rollbackRules();
    void exportBlockedIPsToCSV(const std::string& filename);
    
    void processPacket(const std::string& sourceIP, const std::string& sourcePort,
                       const std::string& destIP, const std::string& destPort, int size,
                       const std::string& protocol = "IP",
                       double payloadEntropy = 0.0, double flagAnomaly = 0.0,
                       const std::string& dnsQueryDomain = "",
                       const std::string& payload = "");
    void runCLI();
    VPNPoolManager* getVpnPool() const { return vpnPool.get(); }
    ThreatIntelSynchronizer* getThreatSync() const { return threatSync.get(); }
    QosManager* getQosManager() const { return qosManager.get(); }
    DeviceMapper* getDeviceMapper() const { return deviceMapper.get(); }
    HoneypotManager* getHoneypotManager() const { return honeypotManager.get(); }
    IpsEngine* getIpsEngine() const { return ipsEngine.get(); }
    DpiClassifier* getDpiClassifier() const { return dpiClassifier.get(); }
    std::string getWebhookUrl() const { return webhookUrl; }
    void setWebhookUrl(const std::string& url) { webhookUrl = url; saveConfig(); }
    void setCategorySchedule(const std::string& category, int start, int end, bool enabled);
    std::vector<LivePacketRecord> getRecentPackets();
    void clearRecentPackets();

    void setKnockConfig(const std::vector<int>& seq, int window, int target, int duration);
    std::vector<int> getKnockSequence() const { return knockSequence; }
    int getKnockWindow() const { return knockWindowSeconds; }
    int getKnockTargetPort() const { return knockTargetPort; }
    int getKnockDuration() const { return knockOpenDurationSeconds; }
    void setDnsSinkholeEnabled(bool enabled) { dnsSinkholeEnabled = enabled; saveConfig(); }
    bool isDnsSinkholeEnabled() const { return dnsSinkholeEnabled; }

    std::string getInterfaceName() const { return interfaceName; }
    std::string getCurrentMacAddress();
    bool setMacAddress(const std::string& macAddress);
    std::string generateRandomMacAddress();
};

#endif // FIREWALL_MANAGER_H