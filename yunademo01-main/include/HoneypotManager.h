#ifndef HONEYPOT_MANAGER_H
#define HONEYPOT_MANAGER_H

#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>

struct HoneypotTriggerRecord {
    std::string timestamp;
    std::string violatorIP;
    int port;
    std::string status; // e.g. "Blocked", "Flagged"
};

class HoneypotManager {
private:
    std::vector<int> trapPorts;
    std::vector<HoneypotTriggerRecord> triggers;
    std::vector<std::thread> listenerThreads;
    std::vector<int> listenerSockets;
    std::mutex honeypotMutex;
    std::atomic<bool> running;
    
    std::function<void(const std::string&, int)> triggerCallback;

    void loadHoneypotConfig();
    void saveHoneypotConfig();
    void loadTriggerHistory();
    void saveTriggerHistory();
    void listenOnPort(int port);
    std::string getCurrentTimestamp();

public:
    HoneypotManager();
    ~HoneypotManager();

    void setTriggerCallback(std::function<void(const std::string&, int)> callback);
    
    bool addTrapPort(int port);
    bool removeTrapPort(int port);
    std::vector<int> getTrapPorts();
    
    std::vector<HoneypotTriggerRecord> getTriggers();
    void clearTriggers();
    
    void startHoneypot();
    void stopHoneypot();
    bool isRunning() const { return running.load(); }
};

#endif // HONEYPOT_MANAGER_H
