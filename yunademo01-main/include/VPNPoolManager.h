#ifndef VPN_POOL_MANAGER_H
#define VPN_POOL_MANAGER_H

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

struct VPNProfile {
    std::string name;
    std::string type; // "wireguard" or "openvpn"
    std::string configPath;
    bool isConnected = false;
};

class VPNPoolManager {
private:
    std::vector<VPNProfile> profiles;
    std::string activeProfileName;
    std::mutex poolMutex;
    std::thread healthMonitorThread;
    std::atomic<bool> running;
    int checkIntervalSeconds;
    int pingTimeoutSeconds;
    
    void loadPoolConfig();
    void savePoolConfig();
    std::string executeSystemCommand(const std::string& cmd);
    void monitorHealth();
    bool pingHost(const std::string& host);

public:
    VPNPoolManager();
    ~VPNPoolManager();

    bool addProfile(const std::string& name, const std::string& type, const std::string& configPath);
    bool removeProfile(const std::string& name);
    std::vector<VPNProfile> getProfiles();
    
    bool connectProfile(const std::string& name);
    void disconnectActive();
    bool isVPNConnected();
    std::string getActiveProfileName();
    
    void startHealthMonitor(int intervalSeconds = 15);
    void stopHealthMonitor();
    bool performFailover();
};

#endif // VPN_POOL_MANAGER_H
