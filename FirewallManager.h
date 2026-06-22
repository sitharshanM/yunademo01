#ifndef FIREWALL_MANAGER_H
#define FIREWALL_MANAGER_H

#include <string>

class FirewallManager {
public:
    void blockIPAddress(const std::string& ip);
    void unblockIPAddress(const std::string& ip);
    void blockWebsite(const std::string& website);
    void blockDomain(const std::string& domain, const std::string& category = "");
    void unblockDomain(const std::string& domain);
    void blockCategory(const std::string& category);
    void unblockCategory(const std::string& category);
    void addFirewallRule(const std::string& action, const std::string& direction, 
                        const std::string& source, const std::string& destination, 
                        const std::string& protocol);
    void removeFirewallRule(const std::string& action, const std::string& direction, 
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
};

#endif // FIREWALL_MANAGER_H